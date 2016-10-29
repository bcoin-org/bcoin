/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var co = require('../utils/co');
var Node = require('./node');
var Chain = require('../chain/chain');
var Pool = require('../net/pool');
var WalletDB = require('../wallet/walletdb');
var HTTPServer;

try {
  HTTPServer = require('../http/server');
} catch (e) {
  ;
}

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
    maxPeers: this.options.maxPeers,
    ignoreDiscovery: this.options.ignoreDiscovery,
    selfish: true,
    spv: true
  });

  this.walletdb = new WalletDB({
    network: this.network,
    logger: this.logger,
    client: this,
    db: this.options.db,
    location: this.location('walletdb'),
    witness: this.options.witness,
    maxFiles: this.options.maxFiles,
    noScan: this.options.noScan,
    wipeNoReally: this.options.wipeNoReally,
    resolution: true,
    verify: true
  });

  if (!utils.isBrowser) {
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

utils.inherits(SPVNode, Node);

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
    self.walletdb.addTX(tx).catch(onError);
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
  });

  this.chain.on('connect', function(entry, block) {
    self.walletdb.addBlock(entry, block.txs).catch(onError);
  });

  this.chain.on('disconnect', function(entry, block) {
    self.walletdb.removeBlock(entry).catch(onError);
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
 * Watch address hashes or outpoints.
 * @param {Hash[]} chunks
 * @returns {Promise}
 */

SPVNode.prototype.watchData = function watchData(chunks) {
  var i;

  this.logger.info('Adding %d addresses to filter.', chunks.length);

  for (i = 0; i < chunks.length; i++)
    this.pool.watch(chunks[i], 'hex');

  return Promise.resolve();
};

/**
 * Scan for any missed transactions.
 * Note that this will replay the blockchain sync.
 * @param {Number|Hash} start
 * @returns {Promise}
 */

SPVNode.prototype.scan = function rescan(start) {
  return this.chain.db.replay(start);
};

/**
 * Estimate smart fee (returns network fee rate).
 * @param {Number?} blocks
 * @returns {Promise}
 */

SPVNode.prototype.estimateFee = function estimateFee(blocks) {
  return Promise.resolve(this.network.feeRate);
};

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
 * Expose
 */

module.exports = SPVNode;
