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

  this.loading = false;

  Fullnode.global = this;

  this._init();
}

utils.inherits(Fullnode, bcoin.node);

Fullnode.prototype._init = function _init() {
  var self = this;
  var pending = 3;

  this.loading = true;

  // BlockDB technically needs access to the
  // chain, but that's only once it's being
  // used for tx retrieval.
  this.blockdb = new bcoin.blockdb(this, {
    cache: false
  });

  // Mempool needs access to blockdb.
  this.mempool = new bcoin.mempool(this, {
    rbf: false
  });

  // Chain needs access to blockdb.
  this.chain = new bcoin.chain(this, {
    preload: false
  });

  // Pool needs access to the chain.
  this.pool = new bcoin.pool(this, {
    witness: this.network.type === 'segnet',
    spv: false
  });

  // Miner needs access to the mempool.
  this.miner = new bcoin.miner(this, {
    address: this.options.payoutAddress,
    coinbaseFlags: this.options.coinbaseFlags
  });

  // WalletDB needs access to the network type.
  this.walletdb = new bcoin.walletdb(this, {
    type: this.options.walletdb
  });

  // HTTP needs access to the mempool
  // and blockdb.
  this.http = new bcoin.http(this, {
    key: this.options.httpKey,
    cert: this.options.httpCert
  });

  // Bind to errors
  this.mempool.on('error', function(err) {
    self.emit('error', err);
  });

  this.pool.on('error', function(err) {
    self.emit('error', err);
  });

  this.chain.on('error', function(err) {
    self.emit('error', err);
  });

  // Emit events for any TX we see that's
  // is relevant to one of our wallets.
  this.on('tx', function(tx) {
    return;
    self.walletdb.ownTX(tx, function(err, input, output) {
      if (err)
        return self.emit('error', err);

      if (input || output)
        self.emit('wallet tx', tx, input || [], output || []);
    });
  });

  // Emit events for valid blocks and TXs.
  this.chain.on('block', function(block) {
    self.emit('block', block);
    block.txs.forEach(function(tx) {
      self.emit('tx', tx, block);
    });
  });

  this.mempool.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  // Update the mempool.
  this.chain.on('add block', function(block) {
    self.mempool.addBlock(block);
  });

  this.chain.on('remove block', function(block) {
    self.mempool.removeBlock(block);
  });

  // Handle forks by unconfirming txs
  // in our wallets' tx pools.
  this.chain.on('remove entry', function(entry) {
    self.wallets.forEach(function(wallet) {
      wallet.tx.getAll().forEach(function(tx) {
        if (tx.block === entry.hash || tx.height >= entry.height)
          wallet.tx.unconfirm(tx);
      });
    });
  });

  function load() {
    if (!--pending) {
      self.loading = false;
      self.emit('load');
      self.pool.startSync();
      utils.debug('Node is loaded and syncing.');
    }
  }

  // Create or load the primary wallet.
  this.createWallet({ id: 'primary', passphrase: 'node' }, function(err, wallet) {
    if (err)
      throw err;

    // Set the miner payout address if the
    // programmer didn't pass one in.
    if (!self.miner.address)
      self.miner.address = wallet.getAddress();

    load();
  });

  this.chain.once('load', function() {
    load();
  });

  this.http.listen(this.options.httpPort || 8080, '0.0.0.0', function(err) {
    if (err)
      throw err;

    load();
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
