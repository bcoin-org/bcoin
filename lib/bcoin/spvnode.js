/**
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * SPVNode
 */

function SPVNode(options) {
  if (!(this instanceof SPVNode))
    return new SPVNode(options);

  if (!options)
    options = {};

  bcoin.node.call(this, options);

  this.pool = null;
  this.chain = null;
  this.walletdb = null;

  this.loading = false;

  SPVNode.global = this;

  this._init();
}

utils.inherits(SPVNode, bcoin.node);

SPVNode.prototype._init = function _init() {
  var self = this;
  var options;

  this.loading = true;

  this.chain = new bcoin.chain(this, {
    spv: true,
    preload: true,
    fsync: false
  });

  this.pool = new bcoin.pool(this, {
    witness: this.network.type === 'segnet',
    spv: true
  });

  this.walletdb = new bcoin.walletdb(this);

  this.pool.on('error', function(err) {
    self.emit('error', err);
  });

  this.chain.on('error', function(err) {
    self.emit('error', err);
  });

  this.walletdb.on('error', function(err) {
    self.emit('error', err);
  });

  this.pool.on('tx', function(tx) {
    self.walletdb.addTX(tx, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  this.createWallet(options, function(err, wallet) {
    if (err)
      throw err;

    self.loading = false;
    self.emit('load');
    self.pool.startSync();

    utils.debug('Node is loaded and syncing.');
  });
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
