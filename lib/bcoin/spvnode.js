/**
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;

/**
 * SPVNode
 */

function SPVNode(options) {
  if (!(this instanceof SPVNode))
    return new SPVNode(options);

  if (!options)
    options = {};

  bcoin.node.call(this, options);

  this.loaded = false;

  SPVNode.global = this;

  this._init();
}

utils.inherits(SPVNode, bcoin.node);

SPVNode.prototype._init = function _init() {
  var self = this;
  var options;

  this.wallet = null;

  this.chain = new bcoin.chain(this, {
    preload: this.options.preload,
    spv: true,
    useCheckpoints: this.options.useCheckpoints
  });

  // Pool needs access to the chain.
  this.pool = new bcoin.pool(this, {
    witness: this.network.witness,
    spv: true
  });

  // WalletDB needs access to the network type.
  this.walletdb = new bcoin.walletdb(this);

  this.http = new bcoin.http.server(this, {
    key: this.options.sslKey,
    cert: this.options.sslCert,
    port: this.options.httpPort || 8080,
    host: '0.0.0.0'
  });

  // Bind to errors
  this.pool.on('error', function(err) {
    self.emit('error', err);
  });

  this.chain.on('error', function(err) {
    self.emit('error', err);
  });

  this.http.on('error', function(err) {
    self.emit('error', err);
  });

  this.walletdb.on('error', function(err) {
    self.emit('error', err);
  });

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

  function load(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');
    utils.debug('Node is loaded.');
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
    this.http.open.bind(this.http)
  ], load);
};

SPVNode.prototype.broadcast = function broadcast(item, callback) {
  return this.pool.broadcast(item, callback);
};

SPVNode.prototype.sendTX = function sendTX(item, callback) {
  return this.pool.sendTX(item, callback);
};

SPVNode.prototype.sendBlock = function sendBlock(item, callback) {
  return this.pool.sendBlock(item, callback);
};

SPVNode.prototype.connect = function connect() {
  return this.pool.connect();
};

SPVNode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

SPVNode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

SPVNode.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

SPVNode.prototype.close =
SPVNode.prototype.destroy = function destroy(callback) {
  this.wallet.destroy();
  utils.parallel([
    this.http.close.bind(this.http),
    this.pool.close.bind(this.pool),
    this.walletdb.close.bind(this.walletdb),
    this.chain.close.bind(this.chain)
  ], callback);
};

SPVNode.prototype.createWallet = function createWallet(options, callback) {
  var self = this;
  callback = utils.ensure(callback);
  this.walletdb.create(options, function(err, wallet) {
    if (err)
      return callback(err);

    assert(wallet);

    utils.debug('Loaded wallet with id=%s address=%s',
      wallet.id, wallet.getAddress());

    self.pool.addWallet(wallet, function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  });
};

SPVNode.prototype.getWallet = function getWallet(id, passphrase, callback) {
  return this.walletdb.get(id, passphrase, callback);
};

/**
 * Expose
 */

module.exports = SPVNode;
