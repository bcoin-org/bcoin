/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var Locker = require('../utils/locker');
var Node = require('./node');
var Chain = require('../blockchain/chain');
var Pool = require('../net/pool');
var WalletDB = require('../wallet/walletdb');
var HTTPServer = require('../http/server');

/**
 * Create an spv node which only maintains
 * a chain, a pool, and a wallet database.
 * @exports SPVNode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @param {Buffer?} options.sslKey
 * @param {Buffer?} options.sslCert
 * @param {Number?} options.httpPort
 * @param {String?} options.httpHost
 * @param {Object?} options.wallet - Primary {@link Wallet} options.
 * @property {Boolean} loaded
 * @property {Chain} chain
 * @property {Pool} pool
 * @property {WalletDB} walletdb
 * @property {HTTPServer} http
 * @emits SPVNode#block
 * @emits SPVNode#tx
 * @emits SPVNode#alert
 * @emits SPVNode#error
 */

function SPVNode(options) {
  if (!(this instanceof SPVNode))
    return new SPVNode(options);

  Node.call(this, options);

  this.chain = new Chain({
    network: this.network,
    logger: this.logger,
    db: this.options.db,
    location: this.location('spvchain'),
    witness: this.options.witness,
    forceWitness: this.options.forceWitness,
    useCheckpoints: this.options.useCheckpoints,
    maxFiles: this.options.maxFiles,
    spv: true
  });

  this.pool = new Pool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    witness: this.options.witness,
    proxyServer: this.options.proxyServer,
    preferredSeed: this.options.preferredSeed,
    bip151: this.options.bip151,
    bip150: this.options.bip150,
    authPeers: this.options.authPeers,
    knownPeers: this.options.knownPeers,
    identityKey: this.options.identityKey,
    maxOutbound: this.options.maxOutbound,
    ignoreDiscovery: this.options.ignoreDiscovery,
    headers: this.options.headers,
    selfish: true,
    spv: true
  });

  this.walletdb = new WalletDB({
    network: this.network,
    logger: this.logger,
    client: this.client,
    db: this.options.db,
    location: this.location('walletdb'),
    witness: false,
    maxFiles: this.options.maxFiles,
    startHeight: this.options.startHeight,
    wipeNoReally: this.options.wipeNoReally,
    resolution: true,
    verify: true,
    spv: true
  });

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

  this.rescanJob = null;
  this.scanLock = new Locker();
  this.watchLock = new Locker();

  this._init();
}

util.inherits(SPVNode, Node);

/**
 * Initialize the node.
 * @private
 */

SPVNode.prototype._init = function _init() {
  var self = this;
  var onError = this._error.bind(this);

  // Bind to errors
  this.chain.on('error', onError);
  this.pool.on('error', onError);
  this.walletdb.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  this.pool.on('alert', function(alert) {
    self.emit('alert', alert);
  });

  this.pool.on('tx', function(tx) {
    self.emit('tx', tx);

    if (self.rescanJob)
      return;

    self.walletdb.addTX(tx).catch(onError);
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
  });

  this.chain.on('connect', function(entry, block) {
    if (self.rescanJob) {
      self.watchBlock(entry, block).catch(onError);
      return;
    }

    self.emit('connect', entry, block);
  });

  this.chain.on('disconnect', function(entry, block) {
    self.emit('disconnect', entry);
  });

  this.chain.on('reset', function(tip) {
    self.emit('reset', tip);
  });
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias SPVNode#open
 * @returns {Promise}
 */

SPVNode.prototype._open = co(function* open(callback) {
  yield this.chain.open();
  yield this.pool.open();
  yield this.walletdb.open();

  // Ensure primary wallet.
  yield this.openWallet();

  if (this.http)
    yield this.http.open();

  this.logger.info('Node is loaded.');
});

/**
 * Close the node, wait for the database to close.
 * @alias SPVNode#close
 * @returns {Promise}
 */

SPVNode.prototype._close = co(function* close() {
  if (this.http)
    yield this.http.close();

  yield this.wallet.destroy();

  this.wallet = null;

  yield this.walletdb.close();
  yield this.pool.close();
  yield this.chain.close();
});

/**
 * Scan for any missed transactions.
 * Note that this will replay the blockchain sync.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

SPVNode.prototype.scan = co(function* scan(start, filter, iter) {
  var unlock = yield this.scanLock.lock();
  var height = this.chain.height;

  try {
    yield this.chain.replay(start);

    if (this.chain.height < height) {
      // We need to somehow defer this.
      // yield this.pool.startSync();
      // yield this.watchUntil(height, iter);
    }
  } finally {
    unlock();
  }
});

/**
 * Watch the blockchain until a certain height.
 * @param {Number} height
 * @param {Function} iter
 * @returns {Promise}
 */

SPVNode.prototype.watchUntil = function watchUntil(height, iter) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.rescanJob = new RescanJob(resolve, reject, height, iter);
  });
};

/**
 * Handled watched block.
 * @param {ChainEntry} entry
 * @param {MerkleBlock} block
 * @returns {Promise}
 */

SPVNode.prototype.watchBlock = co(function* watchBlock(entry, block) {
  var unlock = yield this.watchLock.lock();
  try {
    if (entry.height < this.rescanJob.height) {
      yield this.rescanJob.iter(entry, block.txs);
      return;
    }
    this.rescanJob.resolve();
    this.rescanJob = null;
  } catch (e) {
    this.rescanJob.reject(e);
    this.rescanJob = null;
  } finally {
    unlock();
  }
});

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @returns {Promise}
 */

SPVNode.prototype.broadcast = function broadcast(item) {
  return this.pool.broadcast(item);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX} tx
 * @returns {Promise}
 */

SPVNode.prototype.sendTX = function sendTX(tx) {
  return this.pool.broadcast(tx);
};

/**
 * Connect to the network.
 */

SPVNode.prototype.connect = function connect() {
  return this.pool.connect();
};

/**
 * Start the blockchain sync.
 */

SPVNode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

/**
 * Stop syncing the blockchain.
 */

SPVNode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

/*
 * Helpers
 */

function RescanJob(resolve, reject, height, iter) {
  this.resolve = resolve;
  this.reject = reject;
  this.height = height;
  this.iter = iter;
}

/*
 * Expose
 */

module.exports = SPVNode;
