/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var Node = require('./node');
var Chain = require('../blockchain/chain');
var Fees = require('../mempool/fees');
var Mempool = require('../mempool/mempool');
var Pool = require('../net/pool');
var Miner = require('../mining/miner');
var HTTPServer = require('../http/server');
var RPC = require('../http/rpc');

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
    db: this.config.str('db'),
    prefix: this.config.prefix,
    maxFiles: this.config.num('max-files'),
    cacheSize: this.config.mb('cache-size'),
    forceWitness: this.config.bool('force-witness'),
    prune: this.config.bool('prune'),
    checkpoints: this.config.bool('checkpoints'),
    coinCache: this.config.mb('coin-cache'),
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
    chain: this.chain,
    fees: this.fees,
    db: this.config.str('db'),
    prefix: this.config.prefix,
    persistent: this.config.bool('persistent-mempool'),
    maxSize: this.config.num('mempool-size'),
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
  var self = this;
  var onError = this.error.bind(this);

  // Bind to errors
  this.chain.on('error', onError);
  this.mempool.on('error', onError);
  this.pool.on('error', onError);
  this.miner.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  this.mempool.on('tx', function(tx) {
    self.miner.cpu.notifyEntry();
    self.emit('tx', tx);
  });

  this.chain.hook('connect', co(function* (entry, block) {
    try {
      yield self.mempool._addBlock(entry, block.txs);
    } catch (e) {
      self.error(e);
    }
    self.emit('block', block);
    self.emit('connect', entry, block);
  }));

  this.chain.hook('disconnect', co(function* (entry, block) {
    try {
      yield self.mempool._removeBlock(entry, block.txs);
    } catch (e) {
      self.error(e);
    }
    self.emit('disconnect', entry, block);
  }));

  this.chain.hook('reset', co(function* (tip) {
    try {
      yield self.mempool._reset();
    } catch (e) {
      self.error(e);
    }
    self.emit('reset', tip);
  }));

  this.loadPlugins();
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias FullNode#open
 * @returns {Promise}
 */

FullNode.prototype._open = co(function* open() {
  yield this.chain.open();
  yield this.mempool.open();
  yield this.miner.open();
  yield this.pool.open();

  yield this.openPlugins();

  if (this.http)
    yield this.http.open();

  this.logger.info('Node is loaded.');
});

/**
 * Close the node, wait for the database to close.
 * @alias FullNode#close
 * @returns {Promise}
 */

FullNode.prototype._close = co(function* close() {
  if (this.http)
    yield this.http.close();

  yield this.closePlugins();

  yield this.pool.close();
  yield this.miner.close();
  yield this.mempool.close();
  yield this.chain.close();

  this.logger.info('Node is closed.');
});

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

FullNode.prototype.broadcast = co(function* broadcast(item) {
  try {
    yield this.pool.broadcast(item);
  } catch (e) {
    this.emit('error', e);
  }
});

/**
 * Add transaction to mempool, broadcast.
 * @param {TX} tx
 */

FullNode.prototype.sendTX = co(function* sendTX(tx) {
  var missing;

  try {
    missing = yield this.mempool.addTX(tx);
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
});

/**
 * Add transaction to mempool, broadcast. Silence errors.
 * @param {TX} tx
 * @returns {Promise}
 */

FullNode.prototype.relay = co(function* relay(tx) {
  try {
    yield this.sendTX(tx);
  } catch (e) {
    this.error(e);
  }
});

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
  var coin = this.mempool.getCoin(hash, index);

  if (coin)
    return Promise.resolve(coin);

  if (this.mempool.isSpent(hash, index))
    return Promise.resolve();

  return this.chain.db.getCoin(hash, index);
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Address} addresses
 * @returns {Promise} - Returns {@link Coin}[].
 */

FullNode.prototype.getCoinsByAddress = co(function* getCoinsByAddress(addresses) {
  var mempool = this.mempool.getCoinsByAddress(addresses);
  var chain = yield this.chain.db.getCoinsByAddress(addresses);
  var out = [];
  var i, coin, spent;

  for (i = 0; i < chain.length; i++) {
    coin = chain[i];
    spent = this.mempool.isSpent(coin.hash, coin.index);

    if (spent)
      continue;

    out.push(coin);
  }

  for (i = 0; i < mempool.length; i++) {
    coin = mempool[i];
    out.push(coin);
  }

  return out;
});

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Address} addresses
 * @returns {Promise} - Returns {@link TXMeta}[].
 */

FullNode.prototype.getMetaByAddress = co(function* getTXByAddress(addresses) {
  var mempool = this.mempool.getMetaByAddress(addresses);
  var chain = yield this.chain.db.getMetaByAddress(addresses);
  return chain.concat(mempool);
});

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXMeta}.
 */

FullNode.prototype.getMeta = co(function* getMeta(hash) {
  var meta = this.mempool.getMeta(hash);

  if (meta)
    return meta;

  return yield this.chain.db.getMeta(hash);
});

/**
 * Retrieve a spent coin viewpoint from mempool or chain database.
 * @param {TXMeta} meta
 * @returns {Promise} - Returns {@link CoinView}.
 */

FullNode.prototype.getMetaView = co(function* getMetaView(meta) {
  if (meta.height === -1)
    return this.mempool.getSpentView(meta.tx);
  return this.chain.getSpentView(meta.tx);
});

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Address} addresses
 * @returns {Promise} - Returns {@link TX}[].
 */

FullNode.prototype.getTXByAddress = co(function* getTXByAddress(addresses) {
  var mtxs = yield this.getMetaByAddress(addresses);
  var out = [];
  var i, mtx;

  for (i = 0; i < mtxs.length; i++) {
    mtx = mtxs[i];
    out.push(mtx.tx);
  }

  return out;
});

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

FullNode.prototype.getTX = co(function* getTX(hash) {
  var mtx = yield this.getMeta(hash);
  if (!mtx)
    return;
  return mtx.tx;
});

/**
 * Test whether the mempool or chain contains a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

FullNode.prototype.hasTX = co(function* hasTX(hash) {
  if (this.mempool.hasEntry(hash))
    return true;

  return yield this.chain.db.hasTX(hash);
});

/*
 * Expose
 */

module.exports = FullNode;
