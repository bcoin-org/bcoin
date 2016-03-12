/**
 * fullnode.js - full node for bcoin
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
 * Fullnode
 */

function Fullnode(options) {
  if (!(this instanceof Fullnode))
    return new Fullnode(options);

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
  var options;

  this.loading = true;

  this.chain = new bcoin.chain(this, {
    preload: false,
    fsync: false,
    prune: false,
    useCheckpoints: false
  });

  // Mempool needs access to blockdb.
  this.mempool = new bcoin.mempool(this, {
    rbf: false
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
  this.walletdb = new bcoin.walletdb(this);

  // HTTP needs access to the mempool
  // and blockdb.
  this.http = new bcoin.http.server(this, {
    key: this.options.sslKey,
    cert: this.options.sslCert
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

  this.http.on('error', function(err) {
    self.emit('error', err);
  });

  this.walletdb.on('error', function(err) {
    self.emit('error', err);
  });

  // this.on('tx', function(tx) {
  //   self.walletdb.addTX(tx, function(err) {
  //     if (err)
  //       self.emit('error', err);
  //   });
  // });

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
  // this.chain.on('add block', function(block) {
  //   self.mempool.addBlock(block);
  // });

  // this.chain.on('remove block', function(block) {
  //   self.mempool.removeBlock(block);
  //   self.walletdb.removeBlock(block);
  // });

  function load() {
    if (!--pending) {
      self.loading = false;
      self.emit('load');
      self.pool.startSync();
      utils.debug('Node is loaded and syncing.');
    }
  }

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  // Create or load the primary wallet.
  this.createWallet(options, function(err, wallet) {
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
      wallet.id, wallet.getAddress());

    self.pool.addWallet(wallet, function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  });
};

Fullnode.prototype.getWallet = function getWallet(id, passphrase, callback) {
  return this.walletdb.get(id, passphrase, callback);
};

Fullnode.prototype.scanWallet = function scanWallet(wallet, callback) {
  wallet.scan(this.getTXByAddress.bind(this), callback);
};

Fullnode.prototype.getBlock = function getBlock(hash, callback) {
  this.chain.db.getBlock(hash, callback);
};

Fullnode.prototype.getFullBlock = function getFullBlock(hash, callback) {
  this.chain.db.getFullBlock(hash, callback);
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

  this.chain.db.getCoin(hash, index, function(err, coin) {
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

  this.chain.db.getCoinsByAddress(addresses, function(err, coins) {
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

  this.chain.db.getTX(hash, function(err, tx) {
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

  this.chain.db.isSpent(hash, index, callback);
};

Fullnode.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var mempool;

  callback = utils.asyncify(callback);

  mempool = this.mempool.getTXByAddress(addresses);

  this.chain.db.getTXByAddress(addresses, function(err, txs) {
    if (err)
      return callback(err);

    return callback(null, mempool.concat(txs));
  });
};

Fullnode.prototype.fillCoin = function fillCoin(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillCoin(tx))
    return callback();

  this.chain.db.fillCoin(tx, callback);
};

Fullnode.prototype.fillTX = function fillTX(tx, callback) {
  callback = utils.asyncify(callback);

  if (this.mempool.fillTX(tx))
    return callback();

  this.chain.db.fillTX(tx, callback);
};

/**
 * Expose
 */

module.exports = Fullnode;
