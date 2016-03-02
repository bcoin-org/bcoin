/**
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
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

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  if (this.options.debug)
    bcoin.debug = this.options.debug;

  if (this.options.network)
    network.set(this.options.network);

  this.pool = null;
  this.chain = null;
  this.wallet = null;

  this.loading = false;

  SPVNode.global = this;

  this._init();
}

utils.inherits(SPVNode, EventEmitter);

SPVNode.prototype._init = function _init() {
  var self = this;

  this.loading = true;

  if (!this.options.pool)
    this.options.pool = {};

  this.options.pool.spv = true;
  this.options.pool.preload = this.options.pool.preload !== false;

  this.pool = new bcoin.pool(this.options.pool);
  this.chain = this.pool.chain;

  this.walletdb = new bcoin.walletdb(this.options.walletdb);

  this.pool.on('error', function(err) {
    self.emit('error', err);
  });

  this.pool.on('tx', function(tx) {
    self.wallet.addTX(tx);
  });

  if (!this.options.wallet)
    this.options.wallet = {};

  if (!this.options.wallet.id)
    this.options.wallet.id = 'primary';

  if (!this.options.wallet.passphrase)
    this.options.wallet.passphrase = 'node';

  this.walletdb.create(this.options.wallet, function(err, wallet) {
    if (err)
      throw err;

    self.wallet = wallet;

    utils.debug('Loaded wallet with id=%s address=%s',
      wallet.getID(), wallet.getAddress());

    // Handle forks
    self.chain.on('remove entry', function(entry) {
      self.wallet.tx.getAll().forEach(function(tx) {
        if (tx.block === entry.hash || tx.height >= entry.height)
          self.wallet.tx.unconfirm(tx);
      });
    });

    self.pool.addWallet(self.wallet, function(err) {
      if (err)
        throw err;

      self.pool.startSync();

      self.loading = false;
      self.emit('load');
    });
  });
};

/**
 * Expose
 */

module.exports = SPVNode;
