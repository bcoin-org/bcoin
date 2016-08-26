/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
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
    self.walletdb.addTX(tx, onError);
  });

  this.chain.on('block', function(block, entry) {
    self.emit('block', block);
    self.walletdb.addBlock(entry, block.txs, onError);
  });

  this.walletdb.on('save address', function(address, path) {
    self.pool.watch(address.getHash());
  });

  this.walletdb.on('send', function(tx) {
    self.sendTX(tx, onError);
  });
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias SPVNode#open
 * @param {Function} callback
 */

SPVNode.prototype._open = function open(callback) {
  var self = this;
  var options;

  function done(err) {
    if (err)
      return callback(err);

    self.logger.info('Node is loaded.');

    callback();
  }

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  // Create or load the primary wallet.
  utils.serial([
    this.chain.open.bind(this.chain),
    this.pool.open.bind(this.pool),
    this.walletdb.open.bind(this.walletdb),
    function (next) {
      self.walletdb.ensure(options, function(err, wallet) {
        if (err)
          return callback(err);

        self.logger.info('Loaded wallet with id=%s address=%s',
          wallet.id, wallet.getAddress());

        self.wallet = wallet;

        next();
      });
    },
    function(next) {
      var i;
      self.walletdb.getAddressHashes(function(err, hashes) {
        if (err)
          return next(err);

        if (hashes.length > 0)
          self.logger.info('Adding %d addresses to filter.', hashes.length);

        for (i = 0; i < hashes.length; i++)
          self.pool.watch(hashes[i], 'hex');

        next();
      });
    },
    function(next) {
      if (self.options.noScan) {
        self.walletdb.setTip(self.chain.tip.hash, self.chain.height, next);
        return next();
      }

      if (self.walletdb.height === 0)
        return next();

      // Always replay the last block to make
      // sure we didn't miss anything: there
      // is no atomicity between the chaindb
      // and walletdb.
      self.chain.reset(self.walletdb.height - 1, next);
    },
    function(next) {
      // Rebroadcast pending transactions.
      self.wallet.resend(next);
    },
    function(next) {
      if (!self.http)
        return next();
      self.http.open(next);
    }
  ], done);
};

/**
 * Close the node, wait for the database to close.
 * @alias SPVNode#close
 * @param {Function} callback
 */

SPVNode.prototype._close = function close(callback) {
  var self = this;

  this.wallet = null;

  utils.parallel([
    function(next) {
      if (!self.http)
        return next();
      self.http.close(next);
    },
    this.walletdb.close.bind(this.walletdb),
    this.pool.close.bind(this.pool),
    this.chain.close.bind(this.chain)
  ], callback);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @param {Function} callback
 */

SPVNode.prototype.broadcast = function broadcast(item, callback) {
  return this.pool.broadcast(item, callback);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX} tx
 * @param {Function} callback
 */

SPVNode.prototype.sendTX = function sendTX(tx, wait, callback) {
  if (!callback) {
    callback = wait;
    wait = null;
  }

  if (!wait) {
    this.pool.broadcast(tx);
    return utils.nextTick(callback);
  }

  this.pool.broadcast(tx, callback);
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
