/*!
 * fees.js - fee estimation for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Ported from:
 * https://github.com/bitcoin/bitcoin/blob/master/src/policy/fees.cpp
 */

'use strict';

var bcoin = require('./env');
var utils = bcoin.utils;
var assert = require('assert');
var constants = bcoin.protocol.constants;
var global = bcoin.utils.global;
var Float64Array = global.Float64Array || Array;
var Int32Array = global.Int32Array || Array;

/*
 * Constants
 */

var MAX_BLOCK_CONFIRMS = 25;
var DEFAULT_DECAY = 0.998;
var MIN_SUCCESS_PCT = 0.95;
var UNLIKELY_PCT = 0.5;
var SUFFICIENT_FEETXS = 1;
var SUFFICIENT_PRITXS = 0.2;
var MIN_FEERATE = 10;
var MAX_FEERATE = 1e7;
var INF_FEERATE = constants.MAX_MONEY;
var MIN_PRIORITY = 10;
var MAX_PRIORITY = 1e16;
var INF_PRIORITY = 1e9 * constants.MAX_MONEY;
var FEE_SPACING = 1.1;
var PRI_SPACING = 2;
var FREE_THRESHOLD = constants.tx.FREE_THRESHOLD;

/**
 * Confirmation stats.
 * @exposes ConfirmStats
 * @constructor
 * @param {Number} buckets
 * @param {Number} maxConfirms
 * @param {Number} decay
 * @param {String} type
 */

function ConfirmStats(buckets, maxConfirms, decay, type) {
  var i;

  if (!(this instanceof ConfirmStats))
    return new ConfirmStats(buckets, maxConfirms, decay, type);

  this.maxConfirms = maxConfirms;
  this.decay = decay;
  this.type = type;

  this.buckets = new Float64Array(buckets.length);
  this.bucketMap = new DoubleMap();

  for (i = 0; i < buckets.length; i++) {
    this.buckets[i] = buckets[i];
    this.bucketMap.insert(buckets[i], i);
  }

  this.confAvg = new Array(maxConfirms);
  this.curBlockConf = new Array(maxConfirms);
  this.unconfTX = new Array(maxConfirms);

  for (i = 0; i < maxConfirms; i++) {
    this.confAvg[i] = new Float64Array(buckets.length);
    this.curBlockConf[i] = new Int32Array(buckets.length);
    this.unconfTX[i] = new Int32Array(buckets.length);
  }

  this.oldUnconfTX = new Int32Array(buckets.length);
  this.curBlockTX = new Int32Array(buckets.length);
  this.txAvg = new Float64Array(buckets.length);
  this.curBlockVal = new Float64Array(buckets.length);
  this.avg = new Float64Array(buckets.length);
}

/**
 * Clear data for the current block.
 * @param {Number} height
 */

ConfirmStats.prototype.clearCurrent = function clearCurrent(height) {
  var i, j;

  for (i = 0; i < this.buckets.length; i++) {
    this.oldUnconfTX[i] = this.unconfTX[height % this.unconfTX.length][i];
    this.unconfTX[height % this.unconfTX.length][i] = 0;
    for (j = 0; j < this.curBlockConf.length; j++)
      this.curBlockConf[j][i] = 0;
    this.curBlockTX[i] = 0;
    this.curBlockVal[i] = 0;
  }
};

/**
 * Record a rate or priority based on number of blocks to confirm.
 * @param {Number} blocks - Blocks to confirm.
 * @param {Rate|Number} val - Rate or priority.
 */

ConfirmStats.prototype.record = function record(blocks, val) {
  var i, bucketIndex;

  if (blocks < 1)
    return;

  bucketIndex = this.bucketMap.search(val);

  for (i = blocks; i <= this.curBlockConf.length; i++)
    this.curBlockConf[i - 1][bucketIndex]++;

  this.curBlockTX[bucketIndex]++;
  this.curBlockVal[bucketIndex] += val;
};

/**
 * Update moving averages.
 */

ConfirmStats.prototype.updateAverages = function updateAverages() {
  var i, j;

  for (i = 0; i < this.buckets.length; i++) {
    for (j = 0; j < this.confAvg.length; j++) {
      this.confAvg[j][i] =
        this.confAvg[j][i] * this.decay + this.curBlockConf[j][i];
    }
    this.avg[i] = this.avg[i] * this.decay + this.curBlockVal[i];
    this.txAvg[i] = this.txAvg[i] * this.decay + this.curBlockTX[i];
  }
};

/**
 * Estimate the median value for rate or priority.
 * @param {Number} target - Confirmation target.
 * @param {Number} needed - Sufficient tx value.
 * @param {Number} breakpoint - Success break point.
 * @param {Boolean} greater - Whether to look for lowest value.
 * @param {Number} height - Block height.
 * @returns {Rate|Number} Returns -1 on error.
 */

ConfirmStats.prototype.estimateMedian = function estimateMedian(target, needed, breakpoint, greater, height) {
  var conf = 0;
  var total = 0;
  var extra = 0;
  var max = this.buckets.length - 1;
  var start = greater ? max : 0;
  var step = greater ? -1 : 1;
  var near = start;
  var far = start;
  var bestNear = start;
  var bestFar = start;
  var found = false;
  var bins = this.unconfTX.length;
  var i, j, perc, median, sum, minBucket, maxBucket;

  for (i = start; i >= 0 && i <= max; i += step) {
    far = i;
    conf += this.confAvg[target - 1][i];
    total += this.txAvg[i];

    for (j = target; j < this.maxConfirms; j++)
      extra += this.unconfTX[Math.max(height - j, 0) % bins][i];

    extra += this.oldUnconfTX[i];

    if (total >= needed / (1 - this.decay)) {
      perc = conf / (total + extra);

      if (greater && perc < breakpoint)
        break;

      if (!greater && perc > breakpoint)
        break;

      found = true;
      conf = 0;
      total = 0;
      extra = 0;
      bestNear = near;
      bestFar = far;
      near = i + step;
    }
  }

  median = -1;
  sum = 0;

  minBucket = bestNear < bestFar ? bestNear : bestFar;
  maxBucket = bestNear > bestFar ? bestNear : bestFar;

  for (i = minBucket; i <= maxBucket; i++)
    sum += this.txAvg[i];

  if (found && sum !== 0) {
    sum = sum / 2;
    for (j = minBucket; j <= maxBucket; j++) {
      if (this.txAvg[j] < sum) {
        sum -= this.txAvg[j];
      } else {
        median = this.avg[j] / this.txAvg[j];
        break;
      }
    }
  }

  // bcoin.debug('estimatefee: '
  //   + ' For confirmation success in %d blocks'
  //   + ' %s %d need %s %s: %d from buckets %d - %d.'
  //   + ' Current bucket stats %d% %d/%d (%d mempool).',
  //   target,
  //   greater ? '>' : '<',
  //   breakpoint,
  //   this.type,
  //   greater ? '>' : '<',
  //   median,
  //   this.buckets[minBucket],
  //   this.buckets[maxBucket],
  //   100 * conf / Math.max(1, total + extra),
  //   conf,
  //   total,
  //   extra);

  return median;
};

/**
 * Add a transaction's rate/priority to be tracked.
 * @param {Number} height - Block height.
 * @param {Number} val
 * @returns {Number} Bucket index.
 */

ConfirmStats.prototype.addTX = function addTX(height, val) {
  var bucketIndex = this.bucketMap.search(val);
  var blockIndex = height % this.unconfTX.length;
  this.unconfTX[blockIndex][bucketIndex]++;
  bcoin.debug('estimatefee: Adding tx to %s.', this.type);
  return bucketIndex;
};

/**
 * Remove a transaction from tracking.
 * @param {Number} entryHeight
 * @param {Number} bestHeight
 * @param {Number} bucketIndex
 */

ConfirmStats.prototype.removeTX = function removeTX(entryHeight, bestHeight, bucketIndex) {
  var blocksAgo = bestHeight - entryHeight;
  var blockIndex;

  if (bestHeight === 0)
    blocksAgo = 0;

  if (blocksAgo < 0) {
    bcoin.debug('estimatefee: Blocks ago is negative for mempool tx.');
    return;
  }

  if (blocksAgo >= this.unconfTX.length) {
    if (this.oldUnconfTX[bucketIndex] > 0) {
      this.oldUnconfTX[bucketIndex]--;
    } else {
      bcoin.debug('estimatefee:'
        + ' Mempool tx removed >25 blocks (bucket=%d).',
        bucketIndex);
    }
  } else {
    blockIndex = entryHeight % this.unconfTX.length;
    if (this.unconfTX[blockIndex][bucketIndex] > 0) {
      this.unconfTX[blockIndex][bucketIndex]--;
    } else {
      bcoin.debug('estimatefee:'
       + ' Mempool tx removed (block=%d, bucket=%d).',
       blockIndex, bucketIndex);
    }
  }
};

/**
 * Estimator for fees and priority.
 * @exposes PolicyEstimator
 * @constructor
 * @param {Rate} minRelay
 * @param {Network|NetworkType} network
 */

function PolicyEstimator(minRelay, network) {
  var fee, priority, boundary;

  if (!(this instanceof PolicyEstimator))
    return new PolicyEstimator(minRelay, network);

  this.network = bcoin.network.get(network);

  this.minTrackedFee = minRelay < MIN_FEERATE
    ? MIN_FEERATE
    : minRelay;

  fee = [];

  for (boundary = this.minTrackedFee;
       boundary <= MAX_FEERATE;
       boundary *= FEE_SPACING) {
    fee.push(boundary);
  }

  fee.push(INF_FEERATE);

  this.feeStats = new ConfirmStats(
    fee, MAX_BLOCK_CONFIRMS,
    DEFAULT_DECAY, 'FeeRate');

  this.minTrackedPri = FREE_THRESHOLD < MIN_PRIORITY
    ? MIN_PRIORITY
    : FREE_THRESHOLD;

  priority = [];

  for (boundary = this.minTrackedPri;
       boundary <= MAX_PRIORITY;
       boundary *= PRI_SPACING) {
    priority.push(boundary);
  }

  priority.push(INF_PRIORITY);

  this.priStats = new ConfirmStats(
    priority, MAX_BLOCK_CONFIRMS,
    DEFAULT_DECAY, 'Priority');

  this.feeUnlikely = 0;
  this.feeLikely = INF_FEERATE;
  this.priUnlikely = 0;
  this.priLikely = INF_PRIORITY;
  this.map = {};
  this.bestHeight = 0;
}

/**
 * Stop tracking a tx. Remove from map.
 * @param {Hash} hash
 */

PolicyEstimator.prototype.removeTX = function removeTX(hash) {
  var item = this.map[hash];

  if (!item) {
    bcoin.debug('estimatefee: Mempool tx %s not found.', hash);
    return;
  }

  this.feeStats.removeTX(item.blockHeight, this.bestHeight, item.bucketIndex);

  delete this.map[hash];
};

/**
 * Test whether a fee should be used for calculation.
 * @param {Amount} fee
 * @param {Number} priority
 * @returns {Boolean}
 */

PolicyEstimator.prototype.isFeePoint = function isFeePoint(fee, priority) {
  if ((priority < this.minTrackedPri && fee >= this.minTrackedFee)
      || (priority < this.priUnlikely && fee > this.feeLikely)) {
    return true;
  }
  return false;
};

/**
 * Test whether a priority should be used for calculation.
 * @param {Amount} fee
 * @param {Number} priority
 * @returns {Boolean}
 */

PolicyEstimator.prototype.isPriPoint = function isPriPoint(fee, priority) {
  if ((fee < this.minTrackedFee && priority >= this.minTrackedPri)
      || (fee < this.feeUnlikely && priority > this.priLikely)) {
    return true;
  }
  return false;
};

/**
 * Process a mempool entry.
 * @param {MempoolEntry} entry
 * @param {Boolean} current - Whether the chain is synced.
 */

PolicyEstimator.prototype.processTX = function processTX(entry, current) {
  var height = entry.height;
  var hash = entry.tx.hash('hex');
  var fee, rate, priority;

  if (this.map[hash]) {
    bcoin.debug('estimatefee: Mempool tx %s already tracked.', hash);
    return;
  }

  // Ignore reorgs.
  if (height < this.bestHeight)
    return;

  // Wait for chain to sync.
  if (!current)
    return;

  // Requires other mempool txs in order to be confirmed. Ignore.
  if (entry.dependencies)
    return;

  fee = entry.getFee();
  rate = entry.getRate();
  priority = entry.getPriority(height);

  bcoin.debug('estimatefee: Processing mempool tx %s.', hash);

  if (fee === 0 || this.isPriPoint(rate, priority)) {
    this.map[hash] = {
      blockHeight: height,
      bucketIndex: this.priStats.addTX(height, priority)
    };
  } else if (this.isFeePoint(rate, priority)) {
    this.map[hash] = {
      blockHeight: height,
      bucketIndex: this.feeStats.addTX(height, rate)
    };
    bcoin.debug('estimatefee: Rate: %d.', this.estimateFee());
  } else {
    bcoin.debug('estimatefee: Not adding tx %s.', hash);
  }

};

/**
 * Process an entry being removed from the mempool.
 * @param {Number} height - Block height.
 * @param {MempoolEntry} entry
 */

PolicyEstimator.prototype.processBlockTX = function processBlockTX(height, entry) {
  var blocks, fee, rate, priority;

  // Requires other mempool txs in order to be confirmed. Ignore.
  if (entry.dependencies)
    return;

  blocks = height - entry.height;
  if (blocks <= 0) {
    bcoin.debug(
      'estimatefee: Block tx %s had negative blocks to confirm (%d, %d).',
      entry.tx.hash('hex'),
      height,
      entry.height);
    return;
  }

  fee = entry.getFee();
  rate = entry.getRate();
  priority = entry.getPriority(height);

  if (fee === 0 || this.isPriPoint(rate, priority))
    this.priStats.record(blocks, priority);
  else if (this.isFeePoint(rate, priority))
    this.feeStats.record(blocks, rate);
};

/**
 * Process a block of transaction entries being removed from the mempool.
 * @param {Number} height - Block height.
 * @param {MempoolEntry[]} entries
 * @param {Boolean} current - Whether the chain is synced.
 */

PolicyEstimator.prototype.processBlock = function processBlock(height, entries, current) {
  var i;

  // Ignore reorgs.
  if (height <= this.bestHeight)
    return;

  this.bestHeight = height;

  if (entries.length === 0)
    return;

  // Wait for chain to sync.
  if (!current)
    return;

  bcoin.debug('estimatefee: Recalculating dynamic cutoffs.');

  this.feeLikely = this.feeStats.estimateMedian(
    2, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
    true, height);

  if (this.feeLikely === -1)
    this.feeLikely = INF_FEERATE;

  this.feeUnlikely = this.feeStats.estimateMedian(
    10, SUFFICIENT_FEETXS, UNLIKELY_PCT,
    false, height);

  if (this.feeUnlikely === -1)
    this.feeUnlikely = 0;

  this.priLikely = this.priStats.estimateMedian(
    2, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
    true, height);

  if (this.priLikely === -1)
    this.priLikely = INF_PRIORITY;

  this.priUnlikely = this.priStats.estimateMedian(
    10, SUFFICIENT_PRITXS, UNLIKELY_PCT,
    false, height);

  if (this.priUnlikely === -1)
    this.priUnlikely = 0;

  this.feeStats.clearCurrent(height);
  this.priStats.clearCurrent(height);

  for (i = 0; i < entries.length; i++)
    this.processBlockTX(height, entries[i]);

  this.feeStats.updateAverages();
  this.priStats.updateAverages();

  bcoin.debug('estimatefee: Done updating estimates'
    + ' for %d confirmed entries. New mempool map size %d.',
    entries.length, Object.keys(this.map).length);
};

/**
 * Estimate a fee rate.
 * @param {Number} target - Confirmation target.
 * @param {Boolean} [smart=true] - Smart estimation.
 * @returns {Rate}
 */

PolicyEstimator.prototype.estimateFee = function estimateFee(target, smart) {
  var rate, minPoolFee;

  if (!target)
    target = 1;

  if (smart == null)
    smart = true;

  if (!(target > 0) || target > this.feeStats.maxConfirms)
    return 0;

  if (!smart) {
    rate = this.feeStats.estimateMedian(
      target, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
      true, this.bestHeight);

    if (rate < 0)
      return 0;

    return Math.floor(rate);
  }

  rate = -1;
  while (rate < 0 && target <= this.feeStats.maxConfirms) {
    rate = this.feeStats.estimateMedian(
      target++, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
      true, this.bestHeight);
  }

  target -= 1;

  minPoolFee = this.network.minRelay;
  if (minPoolFee > 0 && minPoolFee > rate)
    return minPoolFee;

  if (rate < 0)
    return 0;

  return Math.floor(rate);
};

/**
 * Estimate a priority.
 * @param {Number} target - Confirmation target.
 * @param {Boolean} [smart=true] - Smart estimation.
 * @returns {Number}
 */

PolicyEstimator.prototype.estimatePriority = function estimatePriority(target, smart) {
  var minPoolFee, priority;

  if (!target)
    target = 1;

  if (smart == null)
    smart = true;

  if (!(target > 0) || target > this.priStats.maxConfirms)
    return 0;

  if (!smart) {
    priority = this.priStats.estimateMedian(
      target, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
      true, this.bestHeight);
    return Math.floor(priority);
  }

  minPoolFee = this.network.minRelay;
  if (minPoolFee > 0)
    return INF_PRIORITY;

  priority = -1;
  while (priority < 0 && target <= this.priStats.maxConfirms) {
    priority = this.priStats.estimateMedian(
      target++, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
      true, this.bestHeight);
  }

  target -= 1;

  if (priority < 0)
    return 0;

  return Math.floor(priority);
};

/**
 * DoubleMap
 * @private
 */

function DoubleMap() {
  if (!(this instanceof DoubleMap))
    return new DoubleMap();

  this.buckets = [];
}

DoubleMap.prototype.insert = function insert(key, value) {
  var i = utils.binarySearch(this.buckets, key, compare, true);
  this.buckets.splice(i, 0, [key, value]);
};

DoubleMap.prototype.search = function search(key) {
  var i = utils.binarySearch(this.buckets, key, compare, true);
  assert(this.buckets.length !== 0, 'Cannot search.');
  return this.buckets[i][1];
};

/*
 * Helpers
 */

function compare(a, b) {
  return a[0] - b;
}

/*
 * Expose
 */

exports = PolicyEstimator;
exports.PolicyEstimator = PolicyEstimator;
exports.ConfirmStats = ConfirmStats;

module.exports = exports;
