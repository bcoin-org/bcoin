/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;

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
 * @emits SPVNode#error
 */

function SPVNode(options) {
  if (!(this instanceof SPVNode))
    return new SPVNode(options);

  bcoin.node.call(this, options);

  this.loaded = false;

  this._init();
}

utils.inherits(SPVNode, bcoin.node);

SPVNode.prototype._init = function _init() {
  var self = this;
  var options;

  this.wallet = null;

  this.chain = new bcoin.chain({
    network: this.network,
    preload: this.options.preload,
    useCheckpoints: this.options.useCheckpoints,
    spv: true
  });

  this.pool = new bcoin.pool({
    network: this.network,
    chain: this.chain,
    witness: this.network.witness,
    selfish: true,
    listen: false,
    spv: true
  });

  this.walletdb = new bcoin.walletdb({
    network: this.network,
    verify: true
  });

  if (!utils.isBrowser) {
    this.http = new bcoin.http.server({
      network: this.network,
      node: this,
      key: this.options.sslKey,
      cert: this.options.sslCert,
      port: this.options.httpPort || this.network.rpcPort,
      host: '0.0.0.0'
    });
  }

  // Bind to errors
  this.pool.on('error', function(err) {
    self.emit('error', err);
  });

  this.chain.on('error', function(err) {
    self.emit('error', err);
  });

  this.walletdb.on('error', function(err) {
    self.emit('error', err);
  });

  if (this.http) {
    this.http.on('error', function(err) {
      self.emit('error', err);
    });
  }

  this.on('tx', function(tx) {
    self.walletdb.addTX(tx, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  // Emit events for valid blocks and TXs.
  this.chain.on('block', function(block) {
    self.emit('block', block);
    block.txs.forEach(function(tx) {
      self.emit('tx', tx, block);
    });
  });

  this.pool.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  this.chain.on('remove entry', function(entry) {
    self.walletdb.removeBlockSPV(entry, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  this.walletdb.on('save address', function(hash) {
    self.pool.watch(hash, 'hex');
  });

  function load(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');
    bcoin.debug('Node is loaded.');
  }

  options = utils.merge({
    id: 'primary',
    passphrase: this.options.passphrase
  }, this.options.wallet || {});

  // Create or load the primary wallet.
  utils.serial([
    this.chain.open.bind(this.chain),
    this.pool.open.bind(this.pool),
    function (next) {
      self.walletdb.open(function(err) {
        if (err)
          return next(err);

        self.createWallet(options, function(err, wallet) {
          if (err)
            return next(err);

          self.wallet = wallet;

          next();
        });
      });
    },
    function(next) {
      var i;
      self.walletdb.getAddresses(function(err, hashes) {
        if (err)
          return next(err);

        if (hashes.length > 0)
          bcoin.debug('Adding %d addresses to filter.', hashes.length);

        for (i = 0; i < hashes.length; i++)
          self.pool.watch(hashes[i], 'hex');

        next();
      });
    },
    function(next) {
      var i;
      self.walletdb.getUnconfirmed(function(err, txs) {
        if (err)
          return next(err);

        if (txs.length > 0)
          bcoin.debug('Rebroadcasting %d transactions.', txs.length);

        for (i = 0; i < txs.length; i++)
          self.pool.broadcast(txs[i]);

        next();
      });
    },
    function(next) {
      if (!self.chain.options.preload)
        return next();

      // If we preloaded, we want to reset
      // the chain to our last height.
      self.walletdb.getLastTime(function(err, ts, height) {
        if (err)
          return next(err);

        if (height === -1)
          return next();

        bcoin.debug('Rewinding chain to height %s.', height);

        self.chain.reset(height, next);
      });
    },
    function(next) {
      if (!self.http)
        return next();
      self.http.open(next);
    }
  ], load);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|MTX|Block} item
 * @param {Function} callback
 */

SPVNode.prototype.broadcast = function broadcast(item, callback) {
  return this.pool.broadcast(item, callback);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|MTX} item
 * @param {Function} callback
 */

SPVNode.prototype.sendTX = function sendTX(item, wait, callback) {
  if (!callback) {
    callback = wait;
    wait = null;
  }

  if (!wait) {
    this.pool.broadcast(item);
    return utils.nextTick(callback);
  }

  return this.pool.broadcast(item, callback);
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

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @param {Function} callback
 */

SPVNode.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the node, wait for the database to close.
 * @method
 * @param {Function} callback
 */

SPVNode.prototype.close =
SPVNode.prototype.destroy = function destroy(callback) {
  var self = this;

  this.wallet.destroy();

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
 * Create a {@link Wallet} in the wallet database.
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

SPVNode.prototype.createWallet = function createWallet(options, callback) {
  this.walletdb.ensure(options, function(err, wallet) {
    if (err)
      return callback(err);

    assert(wallet);

    bcoin.debug('Loaded wallet with id=%s address=%s',
      wallet.id, wallet.getAddress());

    return callback(null, wallet);
  });
};

/**
 * Retrieve a wallet from the wallet database.
 * @param {String} id - Wallet ID.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

SPVNode.prototype.getWallet = function getWallet(id, callback) {
  return this.walletdb.get(id, callback);
};

/*
 * Expose
 */

module.exports = SPVNode;
