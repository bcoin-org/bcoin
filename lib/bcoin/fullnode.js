/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var Node = bcoin.node;

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
 * @property {PolicyEstimator} fees
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

  Node.call(this, options);

  // Instantiate blockchain.
  this.chain = new bcoin.chain({
    network: this.network,
    logger: this.logger,
    profiler: this.profiler,
    db: this.db,
    location: this.location('chain'),
    preload: false,
    spv: false,
    witness: this.options.witness,
    prune: this.options.prune,
    useCheckpoints: this.options.useCheckpoints,
    coinCache: this.options.coinCache,
    indexTX: this.options.indexTX,
    indexAddress: this.options.indexAddress
  });

  // Fee estimation.
  this.fees = new bcoin.fees(
    constants.tx.MIN_RELAY,
    this.network,
    this.logger);

  // Mempool needs access to the chain.
  this.mempool = new bcoin.mempool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    fees: this.fees,
    db: 'memory',
    location: this.location('mempool'),
    limitFree: this.options.limitFree,
    limitFreeRelay: this.options.limitFreeRelay,
    requireStandard: this.options.requireStandard,
    rejectInsaneFees: this.options.rejectInsaneFees,
    replaceByFee: this.options.replaceByFee,
    indexAddress: this.options.indexAddress
  });

  // Pool needs access to the chain and mempool.
  this.pool = new bcoin.pool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    mempool: this.mempool,
    witness: this.options.witness,
    selfish: this.options.selfish,
    headers: this.options.headers,
    compact: this.options.compact,
    bip151: this.options.bip151,
    maxPeers: this.options.maxPeers,
    maxLeeches: this.options.maxLeeches,
    proxyServer: this.options.proxyServer,
    preferredSeed: this.options.preferredSeed,
    ignoreDiscovery: this.options.ignoreDiscovery,
    port: this.options.port,
    listen: this.options.listen,
    spv: false
  });

  // Miner needs access to the chain and mempool.
  this.miner = new bcoin.miner({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    mempool: this.mempool,
    fees: this.fees,
    address: this.options.payoutAddress,
    coinbaseFlags: this.options.coinbaseFlags,
    parallel: this.options.parallel
  });

  // Wallet database needs access to fees.
  this.walletdb = new bcoin.walletdb({
    network: this.network,
    logger: this.logger,
    fees: this.fees,
    db: this.db,
    location: this.location('walletdb'),
    witness: this.options.witness,
    useCheckpoints: this.options.useCheckpoints,
    verify: false
  });

  // HTTP needs access to the node.
  if (!utils.isBrowser) {
    this.http = new bcoin.http.server({
      network: this.network,
      logger: this.logger,
      node: this,
      key: this.options.sslKey,
      cert: this.options.sslCert,
      port: this.options.httpPort || this.network.rpcPort,
      host: this.options.httpHost || '0.0.0.0',
      apiKey: this.options.apiKey,
      walletAuth: this.options.walletAuth,
      noAuth: this.options.noAuth
    });
  }

  this._init();
}

utils.inherits(Fullnode, Node);

/**
 * Initialize the node.
 * @private
 */

Fullnode.prototype._init = function _init() {
  var self = this;

  // Bind to errors
  this.mempool.on('error', function(err) {
    self._error(err);
  });

  this.miner.on('error', function(err) {
    self._error(err);
  });

  this.pool.on('error', function(err) {
    self._error(err);
  });

  this.chain.on('error', function(err) {
    self._error(err);
  });

  this.walletdb.on('error', function(err) {
    self._error(err);
  });

  if (this.http) {
    this.http.on('error', function(err) {
      self._error(err);
    });
  }

  this.pool.on('alert', function(details) {
    self.emit('alert', details);
  });

  this.mempool.on('tx', function(tx) {
    self.emit('tx', tx);
    self.walletdb.addTX(tx, function(err) {
      if (err)
        self._error(err);
    });
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
  });

  this.chain.on('connect', function(entry, block) {
    self.walletdb.addBlock(entry, block.txs, function(err) {
      if (err)
        self._error(err);
    });

    if (!self.chain.isFull())
      return;

    self.mempool.addBlock(block, function(err) {
      if (err)
        self._error(err);
    });
  });

  this.chain.on('disconnect', function(entry, block) {
    self.walletdb.removeBlock(entry, function(err) {
      if (err)
        self._error(err);
    });

    if (!self.chain.isFull())
      return;

    self.mempool.removeBlock(block, function(err) {
      if (err)
        self._error(err);
    });
  });

  this.miner.on('block', function(block) {
    self.pool.broadcast(block.toInv());
  });

  this.walletdb.on('send', function(tx) {
    self.sendTX(tx, function(err) {
      if (err)
        self.emit('error', err);
    });
  });
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias Fullnode#open
 * @param {Function} callback
 */

Fullnode.prototype._open = function open(callback) {
  var self = this;
  var options;

  function done(err) {
    if (err)
      return callback(err);

    self.logger.info('Node is loaded.');

    callback();
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
    this.walletdb.open.bind(this.walletdb),
    function(next) {
      self.createWallet(options, function(err, wallet) {
        if (err)
          return next(err);

        // Set the miner payout address if the
        // programmer didn't pass one in.
        if (!self.miner.address)
          self.miner.address = wallet.getAddress();

        self.wallet = wallet;

        next();
      });
    },
    function(next) {
      if (self.options.noScan) {
        self.walletdb.writeTip(self.chain.tip.hash, next);
        return next();
      }
      // Always rescan to make sure we didn't miss anything:
      // there is no atomicity between the chaindb and walletdb.
      self.walletdb.rescan(self.chain.db, next);
    },
    function(next) {
      var i;
      self.wallet.getUnconfirmed(function(err, txs) {
        if (err)
          return next(err);

        if (txs.length > 0)
          self.logger.info('Rebroadcasting %d transactions.', txs.length);

        for (i = 0; i < txs.length; i++)
          self.pool.broadcast(txs[i]);

        next();
      });
    },
    function(next) {
      if (!self.http)
        return next();
      self.http.open(next);
    }
  ], done);
};

/**
 * Close the node, wait for the database to close.
 * @alias Fullnode#close
 * @param {Function} callback
 */

Fullnode.prototype._close = function close(callback) {
  var self = this;

  this.wallet = null;

  utils.serial([
    function(next) {
      if (!self.http)
        return next();
      self.http.close(next);
    },
    this.walletdb.close.bind(this.walletdb),
    this.pool.close.bind(this.pool),
    this.miner.close.bind(this.miner),
    this.mempool.close.bind(this.mempool),
    this.chain.close.bind(this.chain)
  ], callback);
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

    if (!self.pool.options.selfish)
      item = item.toInv();

    if (!wait) {
      self.pool.broadcast(item);
      return callback();
    }

    return self.pool.broadcast(item, callback);
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
 * Create a {@link Wallet} in the wallet database.
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Fullnode.prototype.createWallet = function createWallet(options, callback) {
  var self = this;
  this.walletdb.ensure(options, function(err, wallet) {
    if (err)
      return callback(err);

    assert(wallet);

    self.logger.info('Loaded wallet with id=%s address=%s',
      wallet.id, wallet.getAddress());

    return callback(null, wallet);
  });
};

/**
 * Retrieve a wallet from the wallet database.
 * @param {String} id - Wallet ID.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Fullnode.prototype.getWallet = function getWallet(id, callback) {
  return this.walletdb.get(id, callback);
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
