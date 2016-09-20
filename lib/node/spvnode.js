/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var Node = bcoin.node;

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

  this.chain = new bcoin.chain({
    network: this.network,
    logger: this.logger,
    db: this.options.db,
    location: this.location('spvchain'),
    witness: this.options.witness,
    useCheckpoints: this.options.useCheckpoints,
    maxFiles: this.options.maxFiles,
    spv: true
  });

  this.pool = new bcoin.pool({
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

  this.walletdb = new bcoin.walletdb({
    network: this.network,
    logger: this.logger,
    db: this.options.db,
    location: this.location('walletdb'),
    witness: this.options.witness,
    maxFiles: this.options.maxFiles,
    verify: true
  });

  if (!utils.isBrowser) {
    this.http = new bcoin.http.server({
      network: this.network,
      logger: this.logger,
      node: this,
      key: this.options.sslKey,
      cert: this.options.sslCert,
      port: this.options.httpPort || this.network.rpcPort,
      host: this.options.httpHost || '0.0.0.0',
      apiKey: this.options.apiKey,
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

  this.chain.on('block', function(block, entry) {
    self.emit('block', block);
    self.walletdb.addBlock(entry, block.txs).catch(onError);
  });

  this.walletdb.on('save address', function(address, path) {
    self.pool.watch(address.getHash());
  });

  this.walletdb.on('send', function(tx) {
    self.sendTX(tx).catch(onError);
  });
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias SPVNode#open
 * @param {Function} callback
 */

SPVNode.prototype._open = function open(callback) {
  return spawn(function *() {
    yield this.chain.open();
    yield this.pool.open();
    yield this.walletdb.open();

    // Ensure primary wallet.
    yield this.openWallet();

    // Load bloom filter.
    yield this.openFilter();

    // Rescan for any missed transactions.
    yield this.rescan();

    // Rebroadcast pending transactions.
    yield this.resend();

    if (this.http)
      yield this.http.open();

    this.logger.info('Node is loaded.');
  }, this);
};

/**
 * Close the node, wait for the database to close.
 * @alias SPVNode#close
 * @param {Function} callback
 */

SPVNode.prototype._close = function close() {
  return spawn(function *() {
    this.wallet = null;
    if (this.http)
      yield this.http.close();
    yield this.walletdb.close();
    yield this.pool.close();
    yield this.chain.close();
  }, this);
};

/**
 * Initialize p2p bloom filter for address watching.
 * @param {Function} callback
 */

SPVNode.prototype.openFilter = function openFilter() {
  return spawn(function *() {
    var hashes = yield this.walletdb.getAddressHashes();
    var i;

    if (hashes.length > 0)
      this.logger.info('Adding %d addresses to filter.', hashes.length);

    for (i = 0; i < hashes.length; i++)
      this.pool.watch(hashes[i], 'hex');
  }, this);
};

/**
 * Rescan for any missed transactions.
 * Note that this will replay the blockchain sync.
 * @param {Function} callback
 */

SPVNode.prototype.rescan = function rescan() {
  if (this.options.noScan) {
    return this.walletdb.setTip(
      this.chain.tip.hash,
      this.chain.height);
  }

  if (this.walletdb.height === 0)
    return Promise.resolve(null);

  // Always replay the last block to make
  // sure we didn't miss anything: there
  // is no atomicity between the chaindb
  // and walletdb.
  return this.chain.reset(this.walletdb.height - 1);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @param {Function} callback
 */

SPVNode.prototype.broadcast = function broadcast(item) {
  return this.pool.broadcast(item);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX} tx
 * @param {Function} callback
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
