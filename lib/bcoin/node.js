/**
 * fullnode.js - full node for bcoin
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
 * Fullnode
 */

function Fullnode(options) {
  if (!(this instanceof Fullnode))
    return new Fullnode(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  bcoin.node.call(this, options);

  this.options.http = {};

  if (!this.options.wallet)
    this.options.wallet = {};

  if (!this.options.wallet.id)
    this.options.wallet.id = 'primary';

  if (!this.options.wallet.passphrase)
    this.options.wallet.passphrase = 'node';

  this.loading = false;

  Fullnode.global = this;

  this._init();
}

utils.inherits(Fullnode, bcoin.node);

Fullnode.prototype._init = function _init() {
  var self = this;

  this.loading = true;

  // BlockDB and Mempool need to be instantiated
  // first because the chain needs access to them.
  this.blockdb = new bcoin.blockdb(this, {
    cache: false
  });

  this.mempool = new bcoin.mempool(this);

  // Chain is instantiated next. The pool needs it.
  this.chain = new bcoin.chain(this, {
    preload: false
  });

  this.pool = new bcoin.pool(this, {
    witness: this.network.type === 'segnet',
    spv: false
  });

  this.miner = new bcoin.miner(this, this.options.miner);
  this.walletdb = new bcoin.walletdb(this, this.options.walletdb);

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

  this.on('tx', function(tx) {
    self.walletdb.ownTX(tx, function(err, input, output) {
      if (err)
        return self.emit('error', err);

      self.emit('own tx', tx, input, output);
    });
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
    block.txs.forEach(function(tx) {
      self.emit('tx', tx, block);
    });
  });

  this.mempool.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  // Handle forks
  this.chain.on('remove entry', function(entry) {
    self.wallets.forEach(function(wallet) {
      wallet.tx.getAll().forEach(function(tx) {
        if (tx.block === entry.hash || tx.height >= entry.height)
          wallet.tx.unconfirm(tx);
      });
    });
  });

  this.createWallet(this.options.wallet, function(err, wallet) {
    if (err)
      throw err;

    self.miner.address = wallet.getAddress();

    self.pool.startSync();

    self.loading = false;
    self.emit('load');
  });
};

Fullnode.prototype.createWallet = function createWallet(options, callback) {
  var self = this;
  callback = utils.ensure(callback);
  this.walletdb.create(options, function(err, wallet) {
    if (err)
      return callback(err);

    assert(wallet);

    utils.debug('Loaded wallet with id=%s address=%s',
      wallet.getID(), wallet.getAddress());

    self.wallets.push(wallet);

    return callback(null, wallet);

    self.pool.addWallet(wallet, function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  });
};

Fullnode.prototype.scanWallet = function scanWallet(wallet, callback) {
  wallet.scan(this.getTXByAddress.bind(this), callback);
};

Fullnode.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var coin;

  this.blockdb.getBlock(hash, function(err, block) {
    if (err)
      return callback(err);

    if (!block)
      return callback();

    return callback(null, block);
  });
};

Fullnode.prototype.getCoin = function getCoin(hash, index, callback) {
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

Fullnode.prototype.getCoinByAddress = function getCoinByAddress(addresses, callback) {
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

Fullnode.prototype.getTX = function getTX(hash, callback) {
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

Fullnode.prototype.isSpent = function isSpent(hash, index, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (this.mempool.isSpent(hash, index))
    return callback(null, true);

  this.blockdb.isSpent(hash, index, callback);
};

Fullnode.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
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

Fullnode.prototype.fillCoin = function fillCoin(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillCoin(tx))
    return callback();

  this.blockdb.fillCoin(tx, callback);
};

Fullnode.prototype.fillTX = function fillTX(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillTX(tx))
    return callback();

  this.blockdb.fillTX(tx, callback);
};

/**
 * Expose
 */

module.exports = Fullnode;
