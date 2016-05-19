/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;

/**
 * Create a fullnode complete with a chain,
 * mempool, miner, wallet, etc.
 * @exports Fullnode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @param {Boolean?} options.limitFree
 * @param {Number?} options.limitFreeRelay
 * @param {Boolean?} options.requireStandard
 * @param {Boolean?} options.rejectInsaneFees
 * @param {Boolean?} options.replaceByFee
 * @param {Boolean?} options.selfish
 * @param {Base58Address?} options.payoutAddress
 * @param {String?} options.coinbaseFlags
 * @param {Buffer?} options.sslKey
 * @param {Buffer?} options.sslCert
 * @param {Number?} options.httpPort
 * @param {String?} options.httpHost
 * @param {Object?} options.wallet - Primary {@link Wallet} options.
 * @property {Boolean} loaded
 * @property {Chain} chain
 * @property {Mempool} mempool
 * @property {Pool} pool
 * @property {Miner} miner
 * @property {WalletDB} walletdb
 * @property {HTTPServer} http
 * @emits Fullnode#block
 * @emits Fullnode#tx
 * @emits Fullnode#error
 */

function Fullnode(options) {
  if (!(this instanceof Fullnode))
    return new Fullnode(options);

  bcoin.node.call(this, options);

  this.loaded = false;

  this._init();
}

utils.inherits(Fullnode, bcoin.node);

Fullnode.prototype._init = function _init() {
  var self = this;
  var options;

  this.wallet = null;

  this.chain = new bcoin.chain({
    network: this.network,
    preload: false,
    spv: false,
    prune: this.options.prune,
    useCheckpoints: this.options.useCheckpoints
  });

  // Mempool needs access to the chain.
  this.mempool = new bcoin.mempool({
    network: this.network,
    chain: this.chain,
    limitFree: this.options.limitFree,
    limitFreeRelay: this.options.limitFreeRelay,
    requireStandard: this.options.requireStandard,
    rejectInsaneFees: this.options.rejectInsaneFees,
    replaceByFee: this.options.replaceByFee
  });

  // Pool needs access to the chain and mempool.
  this.pool = new bcoin.pool({
    network: this.network,
    chain: this.chain,
    mempool: this.mempool,
    witness: this.network.witness,
    selfish: this.options.selfish,
    broadcast: this.options.broadcast,
    spv: false
  });

  // Miner needs access to the chain and mempool.
  this.miner = new bcoin.miner({
    network: this.network,
    chain: this.chain,
    mempool: this.mempool,
    address: this.options.payoutAddress,
    coinbaseFlags: this.options.coinbaseFlags
  });

  this.walletdb = new bcoin.walletdb({
    network: this.network,
    verify: false
  });

  // HTTP needs access to the node.
  this.http = new bcoin.http.server({
    network: this.network,
    node: this,
    key: this.options.sslKey,
    cert: this.options.sslCert,
    port: this.options.httpPort || this.network.rpcPort,
    host: this.options.httpHost || '0.0.0.0'
  });

  // Bind to errors
  this.mempool.on('error', function(err) {
    self.emit('error', err);
  });

  this.miner.on('error', function(err) {
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

  this.chain.on('add block', function(block) {
    self.mempool.addBlock(block, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  this.chain.on('remove block', function(block) {
    self.mempool.removeBlock(block, function(err) {
      if (err)
        self.emit('error', err);
    });
    self.walletdb.removeBlock(block, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  this.miner.on('block', function(block) {
    self.pool.announce(block);
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

  utils.serial([
    this.chain.open.bind(this.chain),
    this.mempool.open.bind(this.mempool),
    this.miner.open.bind(this.miner),
    this.pool.open.bind(this.pool),
    function(next) {
      self.walletdb.open(function(err) {
        if (err)
          return next(err);

        self.createWallet(options, function(err, wallet) {
          if (err)
            return next(err);

          // Set the miner payout address if the
          // programmer didn't pass one in.
          if (!self.miner.address)
            self.miner.address = wallet.getAddress();

          self.wallet = wallet;

          load();
        });
      });
    },
    this.http.open.bind(this.http)
  ], load);
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|MTX|Block} item
 * @param {Function} callback
 */

Fullnode.prototype.broadcast = function broadcast(item, callback) {
  return this.pool.broadcast(item, callback);
};

/**
 * Verify a transaction, add it to the mempool, and broadcast.
 * Safer than {@link Fullnode#broadcast}.
 * @example
 * node.sendTX(tx, callback);
 * node.sendTX(tx, true, callback);
 * @param {TX|MTX} item
 * @param {Boolean?} wait - Wait to execute callback until a node
 * requests our TX, rejects it, or the broadcast itself times out.
 * @param {Function} callback - Returns [{@link VerifyError}|Error].
 */

Fullnode.prototype.sendTX = function sendTX(item, wait, callback) {
  var self = this;

  if (!callback) {
    callback = wait;
    wait = null;
  }

  this.mempool.addTX(item, function(err) {
    if (err)
      return callback(err);

    self.pool.announce(item);

    return callback();
  });
};

/**
 * Listen on a server socket on
 * the p2p network (accepts leech peers).
 */

Fullnode.prototype.listen = function listen(callback) {
  return this.pool.listen(callback);
};

/**
 * Connect to the network.
 */

Fullnode.prototype.connect = function connect() {
  return this.pool.connect();
};

/**
 * Start the blockchain sync.
 */

Fullnode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

/**
 * Stop syncing the blockchain.
 */

Fullnode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @param {Function} callback
 */

Fullnode.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the node, wait for the database to close.
 * @method
 * @param {Function} callback
 */

Fullnode.prototype.close =
Fullnode.prototype.destroy = function destroy(callback) {
  this.wallet.destroy();
  utils.serial([
    this.http.close.bind(this.http),
    this.walletdb.close.bind(this.walletdb),
    this.pool.close.bind(this.pool),
    this.miner.close.bind(this.miner),
    this.mempool.close.bind(this.mempool),
    this.chain.close.bind(this.chain)
  ], callback);
};

/**
 * Create a {@link Wallet} in the wallet database.
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Fullnode.prototype.createWallet = function createWallet(options, callback) {
  var self = this;
  callback = utils.ensure(callback);
  this.walletdb.ensure(options, function(err, wallet) {
    if (err)
      return callback(err);

    assert(wallet);

    bcoin.debug('Loaded wallet with id=%s address=%s',
      wallet.id, wallet.getAddress());

    self.pool.addWallet(wallet, function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  });
};

/**
 * Retrieve a wallet from the wallet database.
 * @param {String} id - Wallet ID.
 * @param {String?} passphrase - Wallet key passphrase.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Fullnode.prototype.getWallet = function getWallet(id, passphrase, callback) {
  return this.walletdb.get(id, passphrase, callback);
};

/**
 * Scan an HD wallet and allocate addresses according to history.
 * @param {Wallet} wallet
 * @param {Function} callback
 */

Fullnode.prototype.scanWallet = function scanWallet(wallet, callback) {
  wallet.scan(this.getTXByAddress.bind(this), callback);
};

/**
 * Retrieve a block from the chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

Fullnode.prototype.getBlock = function getBlock(hash, callback) {
  this.chain.db.getBlock(hash, callback);
};

/**
 * Retrieve a block from the chain database, filled with coins.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

Fullnode.prototype.getFullBlock = function getFullBlock(hash, callback) {
  this.chain.db.getFullBlock(hash, callback);
};

/**
 * Retrieve a coin from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

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

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Fullnode.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
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

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

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

/**
 * Test whether the mempool or chain contains a transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Fullnode.prototype.hasTX = function hasTX(hash, callback) {
  var self = this;

  this.mempool.hasTX(hash, function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback(null, true);

    self.chain.db.hasTX(hash, callback);
  });
};

/**
 * Check whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, Boolean].
 */

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

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

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

/**
 * Fill a transaction with coins from the mempool
 * and chain database (unspent only).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Fullnode.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.mempool.fillAllCoins(tx, callback);
};

/**
 * Fill a transaction with all historical coins
 * from the mempool and chain database.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Fullnode.prototype.fillHistory = function fillHistory(tx, callback) {
  return this.mempool.fillAllHistory(tx, callback);
};

/**
 * Return bitcoinj-style confidence for a transaction.
 * @param {Hash|TX} tx
 * @param {Function} callback - Returns [Error, {@link Confidence}].
 */

Fullnode.prototype.getConfidence = function getConfidence(tx, callback) {
  return this.mempool.getConfidence(tx, callback);
};

/*
 * Expose
 */

module.exports = Fullnode;
