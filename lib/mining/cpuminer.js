/*!
 * cpuminer.js - inefficient cpu miner for bcoin (because we can)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var co = require('../utils/co');
var AsyncObject = require('../utils/asyncobject');
var workerPool = require('../workers/workerpool').pool;
var mine = require('./mine');

/**
 * CPU miner.
 * @alias module:mining.CPUMiner
 * @constructor
 * @param {Miner} miner
 * @emits CPUMiner#block
 * @emits CPUMiner#status
 */

function CPUMiner(miner) {
  if (!(this instanceof CPUMiner))
    return new CPUMiner(miner);

  AsyncObject.call(this);

  this.miner = miner;
  this.network = this.miner.network;
  this.logger = this.miner.logger;
  this.chain = this.miner.chain;

  this.running = false;
  this.stopping = false;
  this.job = null;
  this.since = 0;

  this._init();
}

util.inherits(CPUMiner, AsyncObject);

/**
 * Nonce range interval.
 * @const {Number}
 * @default
 */

CPUMiner.INTERVAL = 0xffffffff / 1500 | 0;

/**
 * Initialize the miner.
 * @private
 */

CPUMiner.prototype._init = function _init() {
  var self = this;

  this.chain.on('tip', function(tip) {
    if (!self.job)
      return;

    if (self.job.attempt.prevBlock === tip.prevBlock)
      self.job.destroy();
  });

  this.on('block', function(block, entry) {
    // Emit the block hex as a failsafe (in case we can't send it)
    self.logger.info('Found block: %d (%s).', entry.height, entry.rhash());
    self.logger.debug('Raw: %s', block.toRaw().toString('hex'));
  });

  this.on('status', function(stat) {
    self.logger.info(
      'CPUMiner: hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
  });
};

/**
 * Open the miner.
 * @method
 * @alias module:mining.CPUMiner#open
 * @returns {Promise}
 */

CPUMiner.prototype._open = co(function* open() {
});

/**
 * Close the miner.
 * @method
 * @alias module:mining.CPUMiner#close
 * @returns {Promise}
 */

CPUMiner.prototype._close = co(function* close() {
  if (!this.running)
    return;

  if (this.stopping) {
    yield this._onStop();
    return;
  }

  yield this.stop();
});

/**
 * Start mining.
 * @method
 * @returns {Promise}
 */

CPUMiner.prototype.start = co(function* start() {
  var block, entry;

  assert(!this.running, 'CPUMiner is already running.');

  this.running = true;
  this.stopping = false;

  for (;;) {
    this.job = null;

    try {
      this.job = yield this.createJob();
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (this.stopping)
      break;

    try {
      block = yield this.mineAsync(this.job);
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (this.stopping)
      break;

    if (!block)
      continue;

    try {
      entry = yield this.chain.add(block);
    } catch (e) {
      if (this.stopping)
        break;
      this.emit('error', e);
      continue;
    }

    if (!entry) {
      this.logger.warning('Mined a bad-prevblk (race condition?)');
      continue;
    }

    if (this.stopping)
      break;

    this.emit('block', block, entry);
  }

  this.emit('done');
});

/**
 * Stop mining.
 * @method
 * @returns {Promise}
 */

CPUMiner.prototype.stop = co(function* stop() {
  assert(this.running, 'CPUMiner is not running.');
  assert(!this.stopping, 'CPUMiner is already stopping.');

  this.stopping = true;

  yield this._onDone();

  this.running = false;
  this.stopping = false;
  this.job = null;

  this.emit('stop');
});

/**
 * Wait for `done` event.
 * @private
 * @returns {Promise}
 */

CPUMiner.prototype._onDone = function _onDone() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('done', resolve);
  });
};

/**
 * Wait for `stop` event.
 * @private
 * @returns {Promise}
 */

CPUMiner.prototype._onStop = function _onStop() {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.once('stop', resolve);
  });
};

/**
 * Create a mining job.
 * @method
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} - Returns {@link Job}.
 */

CPUMiner.prototype.createJob = co(function* createJob(tip, address) {
  var attempt = yield this.miner.createBlock(tip, address);
  return new CPUJob(this, attempt);
});

/**
 * Mine a single block.
 * @method
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} - Returns [{@link Block}].
 */

CPUMiner.prototype.mineBlock = co(function* mineBlock(tip, address) {
  var job = yield this.createJob(tip, address);
  return yield this.mineAsync(job);
});

/**
 * Notify the miner that a new
 * tx has entered the mempool.
 */

CPUMiner.prototype.notifyEntry = function notifyEntry() {
  if (!this.running)
    return;

  if (!this.job)
    return;

  if (++this.since > 20) {
    this.since = 0;
    this.job.destroy();
  }
};

/**
 * Hash until the nonce overflows.
 * @param {CPUJob} job
 * @returns {Number} nonce
 */

CPUMiner.prototype.findNonce = function findNonce(job) {
  var data = job.getHeader(0);
  var target = job.attempt.target;
  var interval = CPUMiner.INTERVAL;
  var min = 0;
  var max = interval;
  var nonce;

  while (max <= 0xffffffff) {
    nonce = mine(data, target, min, max);

    if (nonce !== -1)
      break;

    this.sendStatus(job, max);

    min += interval;
    max += interval;
  }

  return nonce;
};

/**
 * Hash until the nonce overflows.
 * @method
 * @param {CPUJob} job
 * @returns {Promise} Returns Number.
 */

CPUMiner.prototype.findNonceAsync = co(function* findNonceAsync(job) {
  var data = job.getHeader(0);
  var target = job.attempt.target;
  var interval = CPUMiner.INTERVAL;
  var min = 0;
  var max = interval;
  var nonce;

  while (max <= 0xffffffff) {
    nonce = yield workerPool.mine(data, target, min, max);

    if (nonce !== -1)
      break;

    if (job.destroyed)
      return nonce;

    this.sendStatus(job, max);

    min += interval;
    max += interval;
  }

  return nonce;
});

/**
 * Mine synchronously until the block is found.
 * @param {CPUJob} job
 * @returns {Block}
 */

CPUMiner.prototype.mine = function mine(job) {
  var nonce;

  // Track how long we've been at it.
  job.begin = util.now();

  for (;;) {
    nonce = this.findNonce(job);

    if (nonce !== -1)
      break;

    this.iterate(job);
  }

  return job.commit(nonce);
};

/**
 * Mine asynchronously until the block is found.
 * @method
 * @param {CPUJob} job
 * @returns {Promise} - Returns {@link Block}.
 */

CPUMiner.prototype.mineAsync = co(function* mineAsync(job) {
  var nonce;

  // Track how long we've been at it.
  job.begin = util.now();

  for (;;) {
    nonce = yield this.findNonceAsync(job);

    if (nonce !== -1)
      break;

    if (job.destroyed)
      return;

    this.iterate(job);
  }

  return job.commit(nonce);
});

/**
 * Increment extraNonce and send status.
 * @param {CPUJob} job
 */

CPUMiner.prototype.iterate = function iterate(job) {
  job.iterations++;
  job.updateNonce();
  this.sendStatus(job, 0);
};

/**
 * Send a progress report (emits `status`).
 * @param {CPUJob} job
 * @param {Number} nonce
 */

CPUMiner.prototype.sendStatus = function sendStatus(job, nonce) {
  this.emit('status', {
    target: job.attempt.bits,
    hashes: job.getHashes(),
    hashrate: job.getRate(nonce),
    height: job.attempt.height,
    best: util.revHex(job.attempt.prevBlock)
  });
};

/**
 * Mining Job
 * @constructor
 * @ignore
 * @param {CPUMiner} miner
 * @param {BlockTemplate} attempt
 */

function CPUJob(miner, attempt) {
  this.miner = miner;
  this.attempt = attempt;
  this.destroyed = false;
  this.committed = false;
  this.iterations = 0;
  this.begin = 0;
  this.nonce1 = 0;
  this.nonce2 = 0;
  this.refresh();
}

/**
 * Get the raw block header.
 * @param {Number} nonce
 * @returns {Buffer}
 */

CPUJob.prototype.getHeader = function getHeader(nonce) {
  var attempt = this.attempt;
  var n1 = this.nonce1;
  var n2 = this.nonce2;
  var ts = attempt.ts;
  return this.attempt.getHeader(n1, n2, ts, nonce);
};

/**
 * Commit job and return a block.
 * @param {Number} nonce
 * @returns {Block}
 */

CPUJob.prototype.commit = function commit(nonce) {
  var attempt = this.attempt;
  var n1 = this.nonce1;
  var n2 = this.nonce2;
  var ts = attempt.ts;

  assert(!this.committed, 'Job already committed.');
  this.committed = true;

  return this.attempt.commit(n1, n2, ts, nonce);
};

/**
 * Mine block synchronously.
 * @returns {Block}
 */

CPUJob.prototype.mine = function mine() {
  return this.miner.mine(this);
};

/**
 * Mine block asynchronously.
 * @returns {Promise}
 */

CPUJob.prototype.mineAsync = function mineAsync() {
  return this.miner.mineAsync(this);
};

/**
 * Refresh the block template.
 */

CPUJob.prototype.refresh = function refresh() {
  return this.attempt.refresh();
};

/**
 * Increment the extraNonce.
 */

CPUJob.prototype.updateNonce = function() {
  // Overflow the nonce and increment the extraNonce.
  this.nonce1++;

  // Wrap at 4 bytes.
  if (this.nonce1 === 0xffffffff) {
    this.nonce1 = 0;
    this.nonce2++;
  }
};

/**
 * Destroy the job.
 */

CPUJob.prototype.destroy = function() {
  assert(!this.destroyed, 'Job already destroyed.');
  this.destroyed = true;
};

/**
 * Calculate number of hashes.
 * @returns {Number}
 */

CPUJob.prototype.getHashes = function() {
  return this.iterations * 0xffffffff + this.block.nonce;
};

/**
 * Calculate hashrate.
 * @returns {Number}
 */

CPUJob.prototype.getRate = function(nonce) {
  return (nonce / (util.now() - this.begin)) | 0;
};

/**
 * Add a transaction to the block.
 * @param {TX} tx
 * @param {CoinView} view
 */

CPUJob.prototype.addTX = function(tx, view) {
  return this.attempt.addTX(tx, view);
};

/**
 * Add a transaction to the block
 * (less verification than addTX).
 * @param {TX} tx
 * @param {CoinView?} view
 */

CPUJob.prototype.pushTX = function(tx, view) {
  return this.attempt.pushTX(tx, view);
};

/*
 * Expose
 */

module.exports = CPUMiner;
