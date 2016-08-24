/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var assert = utils.assert;
var AsyncObject = require('../utils/async');
var MinerBlock = require('./minerblock');

/**
 * A bitcoin miner (supports mining witness blocks).
 * @exports Miner
 * @constructor
 * @param {Object} options
 * @param {Base58Address} options.address - Payout address.
 * @param {String?} [options.coinbaseFlags="mined by bcoin"]
 * @property {Boolean} running
 * @property {Boolean} loaded
 * @emits Miner#block
 * @emits Miner#status
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  AsyncObject.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.address = bcoin.address(this.options.address);
  this.coinbaseFlags = this.options.coinbaseFlags || 'mined by bcoin';
  this.version = null;

  this.pool = options.pool;
  this.chain = options.chain;
  this.logger = options.logger || this.chain.logger;
  this.mempool = options.mempool;
  this.fees = this.mempool ? this.mempool.fees : options.fees;

  assert(this.chain, 'Miner requires a blockchain.');

  this.network = this.chain.network;
  this.running = false;
  this.timeout = null;
  this.attempt = null;
  this.workerPool = null;

  this._init();
}

utils.inherits(Miner, AsyncObject);

/**
 * Initialize the miner.
 * @private
 */

Miner.prototype._init = function _init() {
  var self = this;

  if (this.mempool) {
    this.mempool.on('tx', function(tx) {
      if (!self.running)
        return;
      if (self.attempt)
        self.attempt.addTX(tx.clone());
    });
  } else if (this.pool) {
    this.pool.on('tx', function(tx) {
      if (!self.running)
        return;
      if (self.attempt)
        self.attempt.addTX(tx.clone());
    });
  }

  this.chain.on('tip', function(tip) {
    if (!self.running)
      return;
    self.stop();
    setTimeout(function() {
      self.start();
    }, self.network.type === 'regtest' ? 100 : 5000);
  });

  this.on('block', function(block) {
    // Emit the block hex as a failsafe (in case we can't send it)
    self.logger.info('Found block: %d (%s).', block.height, block.rhash);
    self.logger.debug('Raw: %s', block.toRaw().toString('hex'));
  });

  this.on('status', function(stat) {
    self.logger.info(
      'Miner: hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });

  if (bcoin.useWorkers) {
    this.workerPool = new bcoin.workers({
      size: this.options.parallel ? 2 : 1,
      timeout: -1
    });

    this.workerPool.on('error', function(err) {
      self.emit('error', err);
    });

    this.workerPool.on('status', function(stat) {
      self.emit('status', stat);
    });
  }
};

/**
 * Open the miner, wait for the chain and mempool to load.
 * @alias Miner#open
 * @param {Function} callback
 */

Miner.prototype._open = function open(callback) {
  var self = this;

  function open(callback) {
    if (self.mempool)
      self.mempool.open(callback);
    else
      self.chain.open(callback);
  }

  open(function(err) {
    if (err)
      return callback(err);

    self.logger.info('Miner loaded (flags=%s).', self.coinbaseFlags);

    callback();
  });
};

/**
 * Close the miner.
 * @alias Miner#close
 * @param {Function} callback
 */

Miner.prototype._close = function close(callback) {
  callback();
};

/**
 * Start mining.
 * @param {Number?} version - Custom block version.
 */

Miner.prototype.start = function start() {
  var self = this;

  this.stop();

  this.running = true;

  // Create a new block and start hashing
  this.createBlock(function(err, attempt) {
    if (err)
      return self.emit('error', err);

    if (!self.running)
      return;

    self.attempt = attempt;

    attempt.on('status', function(status) {
      self.emit('status', status);
    });

    attempt.mineAsync(function(err, block) {
      if (err) {
        if (!self.running)
          return;
        self.emit('error', err);
        return self.start();
      }

      // Add our block to the chain
      self.chain.add(block, function(err) {
        if (err) {
          if (err.type === 'VerifyError')
            self.logger.warning('%s could not be added to chain.', block.rhash);
          self.emit('error', err);
          return self.start();
        }

        // Emit our newly found block
        self.emit('block', block);

        // `tip` will now be emitted by chain
        // and the whole process starts over.
      });
    });
  });
};

/**
 * Stop mining.
 */

Miner.prototype.stop = function stop() {
  if (!this.running)
    return;

  this.running = false;

  if (this.attempt) {
    this.attempt.destroy();
    this.attempt = null;
  }

  if (this.workerPool)
    this.workerPool.destroy();
};

/**
 * Create a block "attempt".
 * @param {Number?} version - Custom block version.
 * @param {Function} callback - Returns [Error, {@link MinerBlock}].
 */

Miner.prototype.createBlock = function createBlock(tip, callback) {
  var self = this;
  var i, ts, attempt, txs, tx;

  if (typeof tip === 'function') {
    callback = tip;
    tip = null;
  }

  if (!tip)
    tip = this.chain.tip;

  ts = Math.max(bcoin.now(), tip.ts + 1);

  function computeVersion(callback) {
    if (self.version != null)
      return callback(null, self.version);
    self.chain.computeBlockVersion(tip, callback);
  }

  if (!this.loaded) {
    this.open(function(err) {
      if (err)
        return callback(err);
      self.createBlock(tip, callback);
    });
    return;
  }

  assert(tip);

  // Find target
  this.chain.getTargetAsync(ts, tip, function(err, target) {
    if (err)
      return callback(err);

    // Calculate version with versionbits
    computeVersion(function(err, version) {
      if (err)
        return callback(err);

      attempt = new MinerBlock({
        workerPool: self.workerPool,
        tip: tip,
        version: version,
        target: target,
        address: self.address,
        coinbaseFlags: self.coinbaseFlags,
        witness: self.chain.segwitActive,
        parallel: self.options.parallel,
        network: self.network
      });

      if (!self.mempool)
        return callback(null, attempt);

      txs = self.mempool.getHistory();

      for (i = 0; i < txs.length; i++) {
        tx = txs[i];
        attempt.addTX(tx);
      }

      callback(null, attempt);
    });
  });
};

/**
 * Mine a single block.
 * @param {Number?} version - Custom block version.
 * @param {Function} callback - Returns [Error, [{@link Block}]].
 */

Miner.prototype.mineBlock = function mineBlock(tip, callback) {
  if (typeof tip === 'function') {
    callback = tip;
    tip = null;
  }

  // Create a new block and start hashing
  this.createBlock(tip, function(err, attempt) {
    if (err)
      return callback(err);

    attempt.mineAsync(callback);
  });
};

Miner.MinerBlock = MinerBlock;

/*
 * Expose
 */

module.exports = Miner;
