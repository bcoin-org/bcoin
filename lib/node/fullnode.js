/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const Node = require('./node');
const Chain = require('../blockchain/chain');
const Fees = require('../mempool/fees');
const Mempool = require('../mempool/mempool');
const Pool = require('../net/pool');
const Miner = require('../mining/miner');
const HTTPServer = require('../http/server');
const RPC = require('../http/rpc');

/**
 * Respresents a fullnode complete with a
 * chain, mempool, miner, etc.
 * @alias module:node.FullNode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @property {Chain} chain
 * @property {PolicyEstimator} fees
 * @property {Mempool} mempool
 * @property {Pool} pool
 * @property {Miner} miner
 * @property {HTTPServer} http
 * @emits FullNode#block
 * @emits FullNode#tx
 * @emits FullNode#connect
 * @emits FullNode#disconnect
 * @emits FullNode#reset
 * @emits FullNode#error
 */

function FullNode(options) {
  if (!(this instanceof FullNode))
    return new FullNode(options);

  Node.call(this, options);

  // SPV flag.
  this.spv = false;

  // Instantiate blockchain.
  this.chain = new Chain({
    network: this.network,
    logger: this.logger,
    workers: this.workers,
    db: this.config.str('db'),
    prefix: this.config.prefix,
    maxFiles: this.config.num('max-files'),
    cacheSize: this.config.mb('cache-size'),
    forceFlags: this.config.bool('force-flags'),
    bip91: this.config.bool('bip91'),
    bip148: this.config.bool('bip148'),
    prune: this.config.bool('prune'),
    checkpoints: this.config.bool('checkpoints'),
    coinCache: this.config.mb('coin-cache'),
    entryCache: this.config.num('entry-cache'),
    indexTX: this.config.bool('index-tx'),
    indexAddress: this.config.bool('index-address')
  });

  // Fee estimation.
  this.fees = new Fees(this.logger);
  this.fees.init();

  // Mempool needs access to the chain.
  this.mempool = new Mempool({
    network: this.network,
    logger: this.logger,
    workers: this.workers,
    chain: this.chain,
    fees: this.fees,
    db: this.config.str('db'),
    prefix: this.config.prefix,
    persistent: this.config.bool('persistent-mempool'),
    maxSize: this.config.mb('mempool-size'),
    limitFree: this.config.bool('limit-free'),
    limitFreeRelay: this.config.num('limit-free-relay'),
    requireStandard: this.config.bool('require-standard'),
    rejectAbsurdFees: this.config.bool('reject-absurd-fees'),
    replaceByFee: this.config.bool('replace-by-fee'),
    indexAddress: this.config.bool('index-address')
  });

  // Pool needs access to the chain and mempool.
  this.pool = new Pool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    mempool: this.mempool,
    prefix: this.config.prefix,
    selfish: this.config.bool('selfish'),
    compact: this.config.bool('compact'),
    bip37: this.config.bool('bip37'),
    bip151: this.config.bool('bip151'),
    bip150: this.config.bool('bip150'),
    identityKey: this.config.buf('identity-key'),
    maxOutbound: this.config.num('max-outbound'),
    maxInbound: this.config.num('max-inbound'),
    proxy: this.config.str('proxy'),
    onion: this.config.bool('onion'),
    upnp: this.config.bool('upnp'),
    seeds: this.config.array('seeds'),
    nodes: this.config.array('nodes'),
    only: this.config.array('only'),
    publicHost: this.config.str('public-host'),
    publicPort: this.config.num('public-port'),
    host: this.config.str('host'),
    port: this.config.num('port'),
    listen: this.config.bool('listen'),
    persistent: this.config.bool('persistent')
  });

  // Miner needs access to the chain and mempool.
  this.miner = new Miner({
    network: this.network,
    logger: this.logger,
    workers: this.workers,
    chain: this.chain,
    mempool: this.mempool,
    address: this.config.array('coinbase-address'),
    coinbaseFlags: this.config.str('coinbase-flags'),
    preverify: this.config.bool('preverify'),
    maxWeight: this.config.num('max-weight'),
    reservedWeight: this.config.num('reserved-weight'),
    reservedSigops: this.config.num('reserved-sigops')
  });

  // RPC needs access to the node.
  this.rpc = new RPC(this);

  // HTTP needs access to the node.
  if (!HTTPServer.unsupported) {
    this.http = new HTTPServer({
      network: this.network,
      logger: this.logger,
      node: this,
      prefix: this.config.prefix,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('http-host'),
      port: this.config.num('http-port'),
      apiKey: this.config.str('api-key'),
      noAuth: this.config.bool('no-auth')
    });
  }

  this._init();
}

util.inherits(FullNode, Node);

/**
 * Initialize the node.
 * @private
 */

FullNode.prototype._init = function _init() {
  // Bind to errors
  this.chain.on('error', err => this.error(err));
  this.mempool.on('error', err => this.error(err));
  this.pool.on('error', err => this.error(err));
  this.miner.on('error', err => this.error(err));

  if (this.http)
    this.http.on('error', err => this.error(err));

  this.mempool.on('tx', (tx) => {
    this.miner.cpu.notifyEntry();
    this.emit('tx', tx);
  });

  this.chain.hook('connect', async (entry, block) => {
    try {
      await this.mempool._addBlock(entry, block.txs);
    } catch (e) {
      this.error(e);
    }
    this.emit('block', block);
    this.emit('connect', entry, block);
  });

  this.chain.hook('disconnect', async (entry, block) => {
    try {
      await this.mempool._removeBlock(entry, block.txs);
    } catch (e) {
      this.error(e);
    }
    this.emit('disconnect', entry, block);
  });

  this.chain.hook('reset', async (tip) => {
    try {
      await this.mempool._reset();
    } catch (e) {
      this.error(e);
    }
    this.emit('reset', tip);
  });

  this.loadPlugins();
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias FullNode#open
 * @returns {Promise}
 */

FullNode.prototype._open = async function open() {
  await this.chain.open();
  await this.mempool.open();
  await this.miner.open();
  await this.pool.open();

  await this.openPlugins();

  if (this.http)
    await this.http.open();

  this.logger.info('Node is loaded.');
};

/**
 * Close the node, wait for the database to close.
 * @alias FullNode#close
 * @returns {Promise}
 */

FullNode.prototype._close = async function close() {
  if (this.http)
    await this.http.close();

  await this.closePlugins();

  await this.pool.close();
  await this.miner.close();
  await this.mempool.close();
  await this.chain.close();

  this.logger.info('Node is closed.');
};

/**
 * Rescan for any missed transactions.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

FullNode.prototype.scan = function scan(start, filter, iter) {
  return this.chain.scan(start, filter, iter);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @returns {Promise}
 */

FullNode.prototype.broadcast = async function broadcast(item) {
  try {
    await this.pool.broadcast(item);
  } catch (e) {
    this.emit('error', e);
  }
};

/**
 * Add transaction to mempool, broadcast.
 * @param {TX} tx
 */

FullNode.prototype.sendTX = async function sendTX(tx) {
  let missing;

  try {
    missing = await this.mempool.addTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError' && err.score === 0) {
      this.error(err);
      this.logger.warning('Verification failed for tx: %s.', tx.txid());
      this.logger.warning('Attempting to broadcast anyway...');
      this.broadcast(tx);
      return;
    }
    throw err;
  }

  if (missing) {
    this.logger.warning('TX was orphaned in mempool: %s.', tx.txid());
    this.logger.warning('Attempting to broadcast anyway...');
    this.broadcast(tx);
    return;
  }

  // We need to announce by hand if
  // we're running in selfish mode.
  if (this.pool.options.selfish)
    this.pool.broadcast(tx);
};

/**
 * Add transaction to mempool, broadcast. Silence errors.
 * @param {TX} tx
 * @returns {Promise}
 */

FullNode.prototype.relay = async function relay(tx) {
  try {
    await this.sendTX(tx);
  } catch (e) {
    this.error(e);
  }
};

/**
 * Connect to the network.
 * @returns {Promise}
 */

FullNode.prototype.connect = function connect() {
  return this.pool.connect();
};

/**
 * Disconnect from the network.
 * @returns {Promise}
 */

FullNode.prototype.disconnect = function disconnect() {
  return this.pool.disconnect();
};

/**
 * Start the blockchain sync.
 */

FullNode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

/**
 * Stop syncing the blockchain.
 */

FullNode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

/**
 * Retrieve a block from the chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

FullNode.prototype.getBlock = function getBlock(hash) {
  return this.chain.db.getBlock(hash);
};

/**
 * Retrieve a coin from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

FullNode.prototype.getCoin = function getCoin(hash, index) {
  let coin = this.mempool.getCoin(hash, index);

  if (coin)
    return Promise.resolve(coin);

  if (this.mempool.isSpent(hash, index))
    return Promise.resolve();

  return this.chain.db.getCoin(hash, index);
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Address} addrs
 * @returns {Promise} - Returns {@link Coin}[].
 */

FullNode.prototype.getCoinsByAddress = async function getCoinsByAddress(addrs) {
  let mempool = this.mempool.getCoinsByAddress(addrs);
  let chain = await this.chain.db.getCoinsByAddress(addrs);
  let out = [];
  let coin;

  for (coin of chain) {
    let spent = this.mempool.isSpent(coin.hash, coin.index);

    if (spent)
      continue;

    out.push(coin);
  }

  for (coin of mempool)
    out.push(coin);

  return out;
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Address} addrs
 * @returns {Promise} - Returns {@link TXMeta}[].
 */

FullNode.prototype.getMetaByAddress = async function getTXByAddress(addrs) {
  let mempool = this.mempool.getMetaByAddress(addrs);
  let chain = await this.chain.db.getMetaByAddress(addrs);
  return chain.concat(mempool);
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXMeta}.
 */

FullNode.prototype.getMeta = async function getMeta(hash) {
  let meta = this.mempool.getMeta(hash);

  if (meta)
    return meta;

  return await this.chain.db.getMeta(hash);
};

/**
 * Retrieve a spent coin viewpoint from mempool or chain database.
 * @param {TXMeta} meta
 * @returns {Promise} - Returns {@link CoinView}.
 */

FullNode.prototype.getMetaView = async function getMetaView(meta) {
  if (meta.height === -1)
    return this.mempool.getSpentView(meta.tx);
  return this.chain.getSpentView(meta.tx);
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Address} addrs
 * @returns {Promise} - Returns {@link TX}[].
 */

FullNode.prototype.getTXByAddress = async function getTXByAddress(addrs) {
  let mtxs = await this.getMetaByAddress(addrs);
  let out = [];

  for (let mtx of mtxs)
    out.push(mtx.tx);

  return out;
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

FullNode.prototype.getTX = async function getTX(hash) {
  let mtx = await this.getMeta(hash);
  if (!mtx)
    return;
  return mtx.tx;
};

/**
 * Test whether the mempool or chain contains a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

FullNode.prototype.hasTX = async function hasTX(hash) {
  if (this.mempool.hasEntry(hash))
    return true;

  return await this.chain.db.hasTX(hash);
};

/*
 * Expose
 */

module.exports = FullNode;
