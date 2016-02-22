/**
 * node.js - full node for bcoin
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
 * Node
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  if (this.options.debug)
    bcoin.debug = this.options.debug;

  if (this.options.network)
    network.set(this.options.network);

  this.blockdb = null;
  this.mempool = null;
  this.pool = null;
  this.chain = null;
  this.miner = null;
  this.wallet = null;

  this.loading = false;

  Node.global = this;

  this._init();
}

utils.inherits(Node, EventEmitter);

Node.prototype._init = function _init() {
  var self = this;

  this.loading = true;

  if (!this.options.pool)
    this.options.pool = {};

  if (!this.options.miner)
    this.options.miner = {};

  this.blockdb = new bcoin.blockdb(this.options.blockdb);
  this.mempool = new bcoin.mempool(this, this.options.mempool);

  this.options.pool.spv = false;
  this.options.pool.blockdb = this.blockdb;
  this.options.pool.mempool = this.mempool;

  this.pool = new bcoin.pool(this.options.pool);
  this.chain = this.pool.chain;

  this.miner = new bcoin.miner(this.pool, this.options.miner);

  this.walletdb = new bcoin.walletdb(this.options.walletdb);

  this.options.http = {};
  if (this.options.http && bcoin.http) {
    this.http = new bcoin.http(this, this.options.http);
    this.http.listen(this.options.http.port || 8080);
  }

  this.mempool.on('error', function(err) {
    self.emit('error', err);
  });

  this.pool.on('error', function(err) {
    self.emit('error', err);
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

    self.chain.on('block', function(block) {
      block.txs.forEach(function(tx) {
        self.wallet.addTX(tx);
      });
    });

    self.mempool.on('tx', function(tx) {
      self.wallet.addTX(tx);
    });

    self.miner.address = self.wallet.getAddress();

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

Node.prototype.getCoin = function getCoin(hash, index, callback) {
  var self = this;
  var coin;

  callback = utils.asyncify(callback);

  coin = this.mempool.getCoin(hash, index);
  if (coin)
    return callback(null, coin);

  if (this.mempool.isSpent(hash, index))
    return callback(null, null);

  this.blockdb.getCoin(hash, index, function(err, coin) {
    if (err)
      return callback(err);

    if (!coin)
      return callback();

    return callback(null, coin);
  });
};

Node.prototype.getCoinByAddress = function getCoinByAddress(addresses, callback) {
  var self = this;
  var mempool;

  callback = utils.asyncify(callback);

  mempool = this.mempool.getCoinsByAddress(addresses);

  this.blockdb.getCoinsByAddress(addresses, function(err, coins) {
    if (err)
      return callback(err);

    return callback(null, mempool.concat(coins.filter(function(coin) {
      if (self.mempool.isSpent(coin.hash, coin.index))
        return false;
      return true;
    })));
  });
};

Node.prototype.getTX = function getTX(hash, callback) {
  var self = this;
  var tx;

  callback = utils.asyncify(callback);

  tx = this.mempool.getTX(hash);
  if (tx)
    return callback(null, tx);

  this.blockdb.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (!tx)
      return callback();

    return callback(null, tx);
  });
};

Node.prototype.isSpent = function isSpent(hash, index, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (this.mempool.isSpent(hash, index))
    return callback(null, true);

  this.blockdb.isSpent(hash, index, callback);
};

Node.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var mempool;

  callback = utils.asyncify(callback);

  mempool = this.mempool.getTXByAddress(addresses);

  this.blockdb.getTXByAddress(addresses, function(err, txs) {
    if (err)
      return callback(err);

    return callback(null, mempool.concat(txs));
  });
};

Node.prototype.fillCoin = function fillCoin(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillCoin(tx))
    return callback();

  this.blockdb.fillCoin(tx, callback);
};

Node.prototype.fillTX = function fillTX(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillTX(tx))
    return callback();

  this.blockdb.fillTX(tx, callback);
};

/**
 * Expose
 */

module.exports = Node;
