/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var util = require('../utils/util');
var co = require('../utils/co');
var Node = require('./node');
var Chain = require('../blockchain/chain');
var Fees = require('../mempool/fees');
var Mempool = require('../mempool/mempool');
var Pool = require('../net/pool');
var Miner = require('../mining/miner');
var WalletDB = require('../wallet/walletdb');
var HTTPServer = require('../http/server');

/**
 * Create a fullnode complete with a chain,
 * mempool, miner, wallet, etc.
 * @exports FullNode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @param {Boolean?} options.limitFree
 * @param {Number?} options.limitFreeRelay
 * @param {Boolean?} options.requireStandard
 * @param {Boolean?} options.rejectInsaneFees
 * @param {Boolean?} options.replaceByFee
 * @param {Boolean?} options.selfish
 * @param {Base58Address?} options.payoutAddress
 * @param {String?} options.coinbaseFlags
 * @param {Buffer?} options.sslKey
 * @param {Buffer?} options.sslCert
 * @param {Number?} options.httpPort
 * @param {String?} options.httpHost
 * @param {Object?} options.wallet - Primary {@link Wallet} options.
 * @property {Boolean} loaded
 * @property {Chain} chain
 * @property {PolicyEstimator} fees
 * @property {Mempool} mempool
 * @property {Pool} pool
 * @property {Miner} miner
 * @property {WalletDB} walletdb
 * @property {HTTPServer} http
 * @emits FullNode#block
 * @emits FullNode#tx
 * @emits FullNode#alert
 * @emits FullNode#error
 */

function FullNode(options) {
  if (!(this instanceof FullNode))
    return new FullNode(options);

  Node.call(this, options);

  // Instantiate blockchain.
  this.chain = new Chain({
    network: this.network,
    logger: this.logger,
    db: this.options.db,
    location: this.location('chain'),
    preload: false,
    spv: false,
    witness: this.options.witness,
    forceWitness: this.options.forceWitness,
    prune: this.options.prune,
    useCheckpoints: this.options.useCheckpoints,
    coinCache: this.options.coinCache,
    indexTX: this.options.indexTX,
    indexAddress: this.options.indexAddress,
    maxFiles: this.options.maxFiles,
    cacheSize: this.options.cacheSize
  });

  // Fee estimation.
  this.fees = new Fees(
    constants.tx.MIN_RELAY,
    this.network,
    this.logger);

  // Mempool needs access to the chain.
  this.mempool = new Mempool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    fees: this.fees,
    limitFree: this.options.limitFree,
    limitFreeRelay: this.options.limitFreeRelay,
    requireStandard: this.options.requireStandard,
    rejectInsaneFees: this.options.rejectInsaneFees,
    replaceByFee: this.options.replaceByFee,
    indexAddress: this.options.indexAddress
  });

  // Pool needs access to the chain and mempool.
  this.pool = new Pool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    mempool: this.mempool,
    witness: this.options.witness,
    selfish: this.options.selfish,
    headers: this.options.headers,
    compact: this.options.compact,
    bip151: this.options.bip151,
    bip150: this.options.bip150,
    authPeers: this.options.authPeers,
    knownPeers: this.options.knownPeers,
    identityKey: this.options.identityKey,
    maxOutbound: this.options.maxOutbound,
    maxInbound: this.options.maxInbound,
    proxyServer: this.options.proxyServer,
    preferredSeed: this.options.preferredSeed,
    ignoreDiscovery: this.options.ignoreDiscovery,
    port: this.options.port,
    spv: false
  });

  // Miner needs access to the chain and mempool.
  this.miner = new Miner({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    mempool: this.mempool,
    fees: this.fees,
    address: this.options.payoutAddress,
    coinbaseFlags: this.options.coinbaseFlags
  });

  // Wallet database needs access to fees.
  this.walletdb = new WalletDB({
    network: this.network,
    logger: this.logger,
    client: this.client,
    db: this.options.db,
    location: this.location('walletdb'),
    witness: false,
    useCheckpoints: this.options.useCheckpoints,
    maxFiles: this.options.walletMaxFiles,
    cacheSize: this.options.walletCacheSize,
    startHeight: this.options.startHeight,
    wipeNoReally: this.options.wipeNoReally,
    resolution: false,
    verify: false
  });

  // HTTP needs access to the node.
  if (!HTTPServer.unsupported) {
    this.http = new HTTPServer({
      network: this.network,
      logger: this.logger,
      node: this,
      key: this.options.sslKey,
      cert: this.options.sslCert,
      port: this.options.httpPort || this.network.rpcPort,
      host: this.options.httpHost || '0.0.0.0',
      apiKey: this.options.apiKey,
      serviceKey: this.options.serviceKey,
      walletAuth: this.options.walletAuth,
      noAuth: this.options.noAuth
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
  var onError = this._error.bind(this);

  // Bind to errors
  this.chain.on('error', onError);
  this.mempool.on('error', onError);
  this.pool.on('error', onError);
  this.miner.on('error', onError);
  this.walletdb.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  this.pool.on('alert', function(alert) {
    self.emit('alert', alert);
  });

  this.mempool.on('tx', function(tx) {
    self.miner.notifyEntry();
    self.emit('tx', tx);
  });

  this.chain.on('connect', co(function* (entry, block) {
    if (self.chain.synced) {
      try {
        yield self.mempool.addBlock(entry, block.txs);
      } catch (e) {
        self._error(e);
      }
    }
    self.emit('block', block);
    self.emit('connect', entry, block);
  }));

  this.chain.on('disconnect', co(function* (entry, block) {
    if (self.chain.synced) {
      try {
        yield self.mempool.removeBlock(entry, block.txs);
      } catch (e) {
        self._error(e);
      }
    }
    self.emit('disconnect', entry, block);
  }));

  this.chain.on('reset', co(function* (tip) {
    try {
      yield self.mempool.reset();
    } catch (e) {
      self._error(e);
    }
    self.emit('reset', tip);
  }));
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

  if (this.http)
    yield this.http.open();

  yield this.walletdb.open();

  // Ensure primary wallet.
  yield this.openWallet();

  if (this.options.listen)
    yield this.pool.listen();

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

  yield this.wallet.destroy();

  this.wallet = null;

  yield this.walletdb.close();
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
 * Verify a transaction, add it to the mempool, and broadcast.
 * Safer than {@link FullNode#broadcast}.
 * @example
 * node.sendTX(tx, callback);
 * node.sendTX(tx, true, callback);
 * @param {TX} tx
 */

FullNode.prototype.sendTX = co(function* sendTX(tx) {
  var missing;

  try {
    missing = yield this.mempool.addTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError' && err.score === 0) {
      this._error(err);
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
  if (this.options.selfish)
    this.pool.announceTX(tx);
});

/**
 * Listen on a server socket on
 * the p2p network (accepts leech peers).
 */

FullNode.prototype.listen = function listen() {
  return this.pool.listen();
};

/**
 * Connect to the network.
 */

FullNode.prototype.connect = function connect() {
  return this.pool.connect();
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

FullNode.prototype.hasTX = function hasTX(hash) {
  if (this.mempool.hasTX(hash))
    return Promise.resolve(true);

  return this.chain.db.hasTX(hash);
};

/*
 * Expose
 */

module.exports = FullNode;
