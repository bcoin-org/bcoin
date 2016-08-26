/*!
 * fullnode.js - full node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var constants = bcoin.constants;
var utils = require('../utils/utils');
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
 * @emits Fullnode#alert
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
    db: this.options.db,
    location: this.location('chain'),
    preload: false,
    spv: false,
    witness: this.options.witness,
    prune: this.options.prune,
    useCheckpoints: this.options.useCheckpoints,
    coinCache: this.options.coinCache,
    indexTX: this.options.indexTX,
    indexAddress: this.options.indexAddress,
    maxFiles: this.options.maxFiles
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
    bip150: this.options.bip150,
    authPeers: this.options.authPeers,
    knownPeers: this.options.knownPeers,
    identityKey: this.options.identityKey,
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
    db: this.options.db,
    location: this.location('walletdb'),
    witness: this.options.witness,
    useCheckpoints: this.options.useCheckpoints,
    maxFiles: this.options.maxFiles,
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
  var onError = this._error.bind(this);

  // Bind to errors
  this.chain.on('error', onError);
  this.mempool.on('error', onError);
  this.pool.on('error', onError);
  this.miner.on('error', onError);
  this.walletdb.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  this.pool.on('alert', function(alert) {
    self.emit('alert', alert);
  });

  this.mempool.on('tx', function(tx) {
    self.emit('tx', tx);
    self.walletdb.addTX(tx, onError);
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
  });

  this.chain.on('connect', function(entry, block) {
    self.walletdb.addBlock(entry, block.txs, onError);

    if (self.chain.synced)
      self.mempool.addBlock(block, onError);
  });

  this.chain.on('disconnect', function(entry, block) {
    self.walletdb.removeBlock(entry, onError);

    if (self.chain.synced)
      self.mempool.removeBlock(block, onError);
  });

  this.miner.on('block', function(block) {
    self.broadcast(block.toInv());
  });

  this.walletdb.on('send', function(tx) {
    self.sendTX(tx, onError);
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

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  utils.serial([
    this.chain.open.bind(this.chain),
    this.mempool.open.bind(this.mempool),
    this.miner.open.bind(this.miner),
    this.pool.open.bind(this.pool),
    this.walletdb.open.bind(this.walletdb),
    function (next) {
      self.walletdb.ensure(options, function(err, wallet) {
        if (err)
          return callback(err);

        self.logger.info('Loaded wallet with id=%s address=%s',
          wallet.id, wallet.getAddress());

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
        self.walletdb.setTip(self.chain.tip.hash, self.chain.height, next);
        return next();
      }

      // Always rescan to make sure we didn't
      // miss anything: there is no atomicity
      // between the chaindb and walletdb.
      self.walletdb.rescan(self.chain.db, next);
    },
    function(next) {
      // Rebroadcast pending transactions.
      self.wallet.resend(next);
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
 * @param {TX|Block} item
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
 * @param {TX} tx
 * @param {Boolean?} wait - Wait to execute callback until a node
 * requests our TX, rejects it, or the broadcast itself times out.
 * @param {Function} callback - Returns [{@link VerifyError}|Error].
 */

Fullnode.prototype.sendTX = function sendTX(tx, wait, callback) {
  var self = this;

  if (!callback) {
    callback = wait;
    wait = null;
  }

  this.mempool.addTX(tx, function(err) {
    if (err) {
      if (err.type === 'VerifyError') {
        self._error(err);
        self.logger.warning('Verification failed for tx: %.', tx.rhash);
        self.logger.warning('Attempting to broadcast anyway...');
        if (!wait) {
          self.pool.broadcast(tx);
          return callback();
        }
        return self.pool.broadcast(tx, callback);
      }
      return callback(err);
    }

    if (!self.options.selfish)
      tx = tx.toInv();

    if (!wait) {
      self.pool.broadcast(tx);
      return callback();
    }

    self.pool.broadcast(tx, callback);
  });
};

/**
 * Listen on a server socket on
 * the p2p network (accepts leech peers).
 */

Fullnode.prototype.listen = function listen(callback) {
  this.pool.listen(callback);
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
  var coin = this.mempool.getCoin(hash, index);

  if (coin)
    return callback(null, coin);

  if (this.mempool.isSpent(hash, index))
    return callback();

  this.chain.db.getCoin(hash, index, callback);
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Address} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Fullnode.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var self = this;
  var coins = this.mempool.getCoinsByAddress(addresses);
  var i, coin, spent;

  this.chain.db.getCoinsByAddress(addresses, function(err, blockCoins) {
    if (err)
      return callback(err);

    for (i = 0; i < blockCoins.length; i++) {
      coin = blockCoins[i];
      spent = self.mempool.isSpent(coin.hash, coin.index);

      if (!spent)
        coins.push(coin);
    }

    callback(null, coins);
  });
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Address} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Fullnode.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var mempool = this.mempool.getTXByAddress(addresses);

  this.chain.db.getTXByAddress(addresses, function(err, txs) {
    if (err)
      return callback(err);

    callback(null, mempool.concat(txs));
  });
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Fullnode.prototype.getTX = function getTX(hash, callback) {
  var tx = this.mempool.getTX(hash);

  if (tx)
    return callback(null, tx);

  this.chain.db.getTX(hash, callback);
};

/**
 * Test whether the mempool or chain contains a transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, Boolean].
 */

Fullnode.prototype.hasTX = function hasTX(hash, callback) {
  if (this.mempool.hasTX(hash))
    return callback(null, true);

  this.chain.db.hasTX(hash, callback);
};

/**
 * Check whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, Boolean].
 */

Fullnode.prototype.isSpent = function isSpent(hash, index, callback) {
  if (this.mempool.isSpent(hash, index))
    return callback(null, true);

  this.chain.db.isSpent(hash, index, callback);
};

/**
 * Fill a transaction with coins from the mempool
 * and chain database (unspent only).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Fullnode.prototype.fillCoins = function fillCoins(tx, callback) {
  this.mempool.fillAllCoins(tx, callback);
};

/**
 * Fill a transaction with all historical coins
 * from the mempool and chain database.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Fullnode.prototype.fillHistory = function fillHistory(tx, callback) {
  this.mempool.fillAllHistory(tx, callback);
};

/**
 * Return bitcoinj-style confidence for a transaction.
 * @param {Hash|TX} tx
 * @param {Function} callback - Returns [Error, {@link Confidence}].
 */

Fullnode.prototype.getConfidence = function getConfidence(tx, callback) {
  this.mempool.getConfidence(tx, callback);
};

/*
 * Expose
 */

module.exports = Fullnode;
