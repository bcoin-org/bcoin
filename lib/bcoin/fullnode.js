/**
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;

/**
 * Fullnode
 */

function Fullnode(options) {
  if (!(this instanceof Fullnode))
    return new Fullnode(options);

  if (!options)
    options = {};

  bcoin.node.call(this, options);

  this.loaded = false;

  Fullnode.global = this;

  this._init();
}

utils.inherits(Fullnode, bcoin.node);

Fullnode.prototype._init = function _init() {
  var self = this;
  var pending = 5;
  var options;

  this.chain = new bcoin.chain(this, {
    preload: false,
    fsync: false,
    spv: false,
    prune: this.options.prune,
    useCheckpoints: this.options.useCheckpoints
  });

  // Mempool needs access to blockdb.
  this.mempool = new bcoin.mempool(this, {
    limitFree: this.options.limitFree,
    limitFreeRelay: this.options.limitFreeRelay,
    requireStandard: this.options.requireStandard,
    rejectInsaneFees: this.options.rejectInsaneFees,
    replaceByFee: this.options.replaceByFee
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
    cert: this.options.sslCert,
    port: this.options.httpPort || 8080,
    host: '0.0.0.0'
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

  this.mempool.on('tx', function(tx) {
    self.emit('tx', tx);
  });

  // Update the mempool.
  this.chain.on('add block', function(block) {
    self.mempool.addBlock(block);
  });

  this.chain.on('remove block', function(block) {
    self.mempool.removeBlock(block);
    self.walletdb.removeBlock(block);
  });

  function load(err) {
    if (err)
      return self.emit('error', err);

    if (!--pending) {
      self.loaded = true;
      self.emit('open');
      utils.debug('Node is loaded.');
    }
  }

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  // Create or load the primary wallet.
  this.walletdb.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.createWallet(options, function(err, wallet) {
      if (err)
        throw err;

      // Set the miner payout address if the
      // programmer didn't pass one in.
      if (!self.miner.address)
        self.miner.address = wallet.getAddress();

      load();
    });
  });

  this.chain.open(load);
  this.mempool.open(load);
  this.pool.open(load);
  this.http.open(load);
};

Fullnode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

Fullnode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

Fullnode.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
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
  this.mempool.getCoin(hash, index, function(err, coin) {
    if (err)
      return callback(err);

    if (coin)
      return callback(null, coin);

    self.chain.db.getCoin(hash, index, function(err, coin) {
      if (err)
        return callback(err);

      if (!coin)
        return callback();

      self.mempool.isSpent(hash, index, function(err, spent) {
        if (err)
          return callback(err);

        if (spent)
          return callback();

        return callback(null, coin);
      });
    });
  });
};

Fullnode.prototype.getCoinByAddress = function getCoinByAddress(addresses, callback) {
  var self = this;
  this.mempool.getCoinsByAddress(addresses, function(err, coins) {
    if (err)
      return callback(err);

    self.chain.db.getCoinsByAddress(addresses, function(err, blockCoins) {
      if (err)
        return callback(err);

      utils.forEach(blockCoins, function(coin, next) {
        self.mempool.isSpent(coin.hash, coin.index, function(err, spent) {
          if (err)
            return callback(err);

          if (!spent)
            coins.push(coin);

          return next();
        });
      }, function(err) {
        if (err)
          return callback(err);
        return callback(null, coins);
      });
    });
  });
};

Fullnode.prototype.getTX = function getTX(hash, callback) {
  var self = this;

  this.mempool.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);

    if (tx)
      return callback(null, tx);

    self.chain.db.getTX(hash, function(err, tx) {
      if (err)
        return callback(err);

      if (!tx)
        return callback();

      return callback(null, tx);
    });
  });
};

Fullnode.prototype.hasTX = function hasTX(hash, callback) {
  var self = this;
  return this.getTX(hash, function(err, tx) {
    if (err)
      return callback(err);
    return callback(null, !!tx);
  });
};

Fullnode.prototype.isSpent = function isSpent(hash, index, callback) {
  var self = this;

  this.mempool.isSpent(hash, index, function(err, spent) {
    if (err)
      return callback(err);

    if (spent)
      return callback(null, true);

    self.chain.db.isSpent(hash, index, callback);
  });
};

Fullnode.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;

  this.mempool.getTXByAddress(addresses, function(err, mempool) {
    if (err)
      return callback(err);

    self.chain.db.getTXByAddress(addresses, function(err, txs) {
      if (err)
        return callback(err);

      return callback(null, mempool.concat(txs));
    });
  });
};

Fullnode.prototype.fillCoin = function fillCoin(tx, callback) {
  var self = this;

  this.mempool.tx.isDoubleSpend(tx, function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, tx, true);

    self.mempool.fillCoin(tx, function(err) {
      if (err)
        return callback(err);

      if (tx.hasPrevout())
        return callback(null, tx);

      self.chain.db.fillCoin(tx, callback);
    });
  });
};

Fullnode.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;

  this.mempool.fillTX(tx, function(err) {
    if (err)
      return callback(err);

    if (tx.hasPrevout())
      return callback(null, tx);

    self.chain.db.fillTX(tx, callback);
  });
};

/**
 * Expose
 */

module.exports = Fullnode;
