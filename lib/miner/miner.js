/*!
 * miner.js - inefficient miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var co = spawn.co;
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

  if (typeof this.coinbaseFlags === 'string')
    this.coinbaseFlags = new Buffer(this.coinbaseFlags, 'utf8');

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
      size: 1,
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
 * @returns {Promise}
 */

Miner.prototype._open = co(function* open() {
  if (this.mempool)
    yield this.mempool.open();
  else
    yield this.chain.open();

  this.logger.info('Miner loaded (flags=%s).',
    this.coinbaseFlags.toString('utf8'));
});

/**
 * Close the miner.
 * @alias Miner#close
 * @returns {Promise}
 */

Miner.prototype._close = function close() {
  return Promise.resolve(null);
};

/**
 * Start mining.
 * @param {Number?} version - Custom block version.
 */

Miner.prototype.start = co(function* start() {
  var self = this;
  var attempt, block;

  this.stop();

  this.running = true;

  // Create a new block and start hashing
  try {
    attempt = yield this.createBlock();
  } catch (e) {
    this.emit('error', e);
    return;
  }

  if (!this.running)
    return;

  this.attempt = attempt;

  attempt.on('status', function(status) {
    self.emit('status', status);
  });

  try {
    block = yield attempt.mineAsync();
  } catch (e) {
    if (!this.running)
      return;
    this.emit('error', e);
    return this.start();
  }

  // Add our block to the chain
  try {
    yield this.chain.add(block);
  } catch (err) {
    if (err.type === 'VerifyError')
      this.logger.warning('%s could not be added to chain.', block.rhash);
    this.emit('error', err);
    this.start();
    return;
  }

  // Emit our newly found block
  this.emit('block', block);

  // `tip` will now be emitted by chain
  // and the whole process starts over.
});

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
 * @returns {Promise} - Returns {@link MinerBlock}.
 */

Miner.prototype.createBlock = co(function* createBlock(tip) {
  var i, ts, attempt, txs, tx, target, version;

  if (!this.loaded)
    yield this.open();

  if (!tip)
    tip = this.chain.tip;

  assert(tip);

  ts = Math.max(bcoin.now(), tip.ts + 1);

  // Find target
  target = yield this.chain.getTargetAsync(ts, tip);

  if (this.version != null) {
    version = this.version;
  } else {
    // Calculate version with versionbits
    version = yield this.chain.computeBlockVersion(tip);
  }

  attempt = new MinerBlock({
    workerPool: this.workerPool,
    tip: tip,
    version: version,
    target: target,
    address: this.address,
    coinbaseFlags: this.coinbaseFlags,
    witness: this.chain.segwitActive,
    network: this.network
  });

  if (!this.mempool)
    return attempt;

  txs = this.mempool.getHistory();

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    attempt.addTX(tx);
  }

  return attempt;
});

/**
 * Mine a single block.
 * @param {Number?} version - Custom block version.
 * @returns {Promise} - Returns [{@link Block}].
 */

Miner.prototype.mineBlock = co(function* mineBlock(tip) {
  // Create a new block and start hashing
  var attempt = yield this.createBlock(tip);
  return yield attempt.mineAsync();
});

/*
 * Expose
 */

module.exports = Miner;
