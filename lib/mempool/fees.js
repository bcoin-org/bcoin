/*!
 * fees.js - fee estimation for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Ported from:
 * https://github.com/bitcoin/bitcoin/blob/master/src/policy/fees.cpp
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
const Logger = require('../node/logger');

/*
 * Constants
 */

const MAX_BLOCK_CONFIRMS = 15; /* 25 */
const DEFAULT_DECAY = 0.998;
const MIN_SUCCESS_PCT = 0.95;
const UNLIKELY_PCT = 0.5;
const SUFFICIENT_FEETXS = 1;
const SUFFICIENT_PRITXS = 0.2;
const MIN_FEERATE = 10;
const MAX_FEERATE = 1e6; /* 1e7 */
const INF_FEERATE = consensus.MAX_MONEY;
const MIN_PRIORITY = 10;
const MAX_PRIORITY = 1e16;
const INF_PRIORITY = 1e9 * consensus.MAX_MONEY;
const FEE_SPACING = 1.1;
const PRI_SPACING = 2;

/**
 * Confirmation stats.
 * @alias module:mempool.ConfirmStats
 * @constructor
 * @param {String} type
 * @param {Logger?} logger
 */

function ConfirmStats(type, logger) {
  if (!(this instanceof ConfirmStats))
    return new ConfirmStats(type, logger);

  this.logger = Logger.global;

  this.type = type;
  this.decay = 0;
  this.maxConfirms = 0;

  this.buckets = new Float64Array(0);
  this.bucketMap = new DoubleMap();

  this.confAvg = [];
  this.curBlockConf = [];
  this.unconfTX = [];

  this.oldUnconfTX = new Int32Array(0);
  this.curBlockTX = new Int32Array(0);
  this.txAvg = new Float64Array(0);
  this.curBlockVal = new Float64Array(0);
  this.avg = new Float64Array(0);

  if (logger) {
    assert(typeof logger === 'object');
    this.logger = logger.context('fees');
  }
}

/**
 * Initialize stats.
 * @param {Array} buckets
 * @param {Number} maxConfirms
 * @param {Number} decay
 * @private
 */

ConfirmStats.prototype.init = function init(buckets, maxConfirms, decay) {
  this.maxConfirms = maxConfirms;
  this.decay = decay;

  this.buckets = new Float64Array(buckets.length);
  this.bucketMap = new DoubleMap();

  for (let i = 0; i < buckets.length; i++) {
    this.buckets[i] = buckets[i];
    this.bucketMap.insert(buckets[i], i);
  }

  this.confAvg = new Array(maxConfirms);
  this.curBlockConf = new Array(maxConfirms);
  this.unconfTX = new Array(maxConfirms);

  for (let i = 0; i < maxConfirms; i++) {
    this.confAvg[i] = new Float64Array(buckets.length);
    this.curBlockConf[i] = new Int32Array(buckets.length);
    this.unconfTX[i] = new Int32Array(buckets.length);
  }

  this.oldUnconfTX = new Int32Array(buckets.length);
  this.curBlockTX = new Int32Array(buckets.length);
  this.txAvg = new Float64Array(buckets.length);
  this.curBlockVal = new Float64Array(buckets.length);
  this.avg = new Float64Array(buckets.length);
};

/**
 * Clear data for the current block.
 * @param {Number} height
 */

ConfirmStats.prototype.clearCurrent = function clearCurrent(height) {
  for (let i = 0; i < this.buckets.length; i++) {
    this.oldUnconfTX[i] = this.unconfTX[height % this.unconfTX.length][i];
    this.unconfTX[height % this.unconfTX.length][i] = 0;
    for (let j = 0; j < this.curBlockConf.length; j++)
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
  let bucketIndex;

  if (blocks < 1)
    return;

  bucketIndex = this.bucketMap.search(val);

  for (let i = blocks; i <= this.curBlockConf.length; i++)
    this.curBlockConf[i - 1][bucketIndex]++;

  this.curBlockTX[bucketIndex]++;
  this.curBlockVal[bucketIndex] += val;
};

/**
 * Update moving averages.
 */

ConfirmStats.prototype.updateAverages = function updateAverages() {
  for (let i = 0; i < this.buckets.length; i++) {
    for (let j = 0; j < this.confAvg.length; j++) {
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
  let conf = 0;
  let total = 0;
  let extra = 0;
  let max = this.buckets.length - 1;
  let start = greater ? max : 0;
  let step = greater ? -1 : 1;
  let near = start;
  let far = start;
  let bestNear = start;
  let bestFar = start;
  let found = false;
  let bins = this.unconfTX.length;
  let median = -1;
  let sum = 0;
  let minBucket, maxBucket;

  for (let i = start; i >= 0 && i <= max; i += step) {
    far = i;
    conf += this.confAvg[target - 1][i];
    total += this.txAvg[i];

    for (let j = target; j < this.maxConfirms; j++)
      extra += this.unconfTX[Math.max(height - j, 0) % bins][i];

    extra += this.oldUnconfTX[i];

    if (total >= needed / (1 - this.decay)) {
      let perc = conf / (total + extra);

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

  minBucket = bestNear < bestFar ? bestNear : bestFar;
  maxBucket = bestNear > bestFar ? bestNear : bestFar;

  for (let i = minBucket; i <= maxBucket; i++)
    sum += this.txAvg[i];

  if (found && sum !== 0) {
    sum = sum / 2;
    for (let j = minBucket; j <= maxBucket; j++) {
      if (this.txAvg[j] < sum) {
        sum -= this.txAvg[j];
      } else {
        median = this.avg[j] / this.txAvg[j];
        break;
      }
    }
  }

  return median;
};

/**
 * Add a transaction's rate/priority to be tracked.
 * @param {Number} height - Block height.
 * @param {Number} val
 * @returns {Number} Bucket index.
 */

ConfirmStats.prototype.addTX = function addTX(height, val) {
  let bucketIndex = this.bucketMap.search(val);
  let blockIndex = height % this.unconfTX.length;
  this.unconfTX[blockIndex][bucketIndex]++;
  this.logger.spam('Adding tx to %s.', this.type);
  return bucketIndex;
};

/**
 * Remove a transaction from tracking.
 * @param {Number} entryHeight
 * @param {Number} bestHeight
 * @param {Number} bucketIndex
 */

ConfirmStats.prototype.removeTX = function removeTX(entryHeight, bestHeight, bucketIndex) {
  let blocksAgo = bestHeight - entryHeight;

  if (bestHeight === 0)
    blocksAgo = 0;

  if (blocksAgo < 0) {
    this.logger.debug('Blocks ago is negative for mempool tx.');
    return;
  }

  if (blocksAgo >= this.unconfTX.length) {
    if (this.oldUnconfTX[bucketIndex] > 0) {
      this.oldUnconfTX[bucketIndex]--;
    } else {
      this.logger.debug('Mempool tx removed >25 blocks (bucket=%d).',
        bucketIndex);
    }
  } else {
    let blockIndex = entryHeight % this.unconfTX.length;
    if (this.unconfTX[blockIndex][bucketIndex] > 0) {
      this.unconfTX[blockIndex][bucketIndex]--;
    } else {
      this.logger.debug('Mempool tx removed (block=%d, bucket=%d).',
       blockIndex, bucketIndex);
    }
  }
};

/**
 * Get serialization size.
 * @returns {Number}
 */

ConfirmStats.prototype.getSize = function getSize() {
  let size = 0;

  size += 8;

  size += sizeArray(this.buckets);
  size += sizeArray(this.avg);
  size += sizeArray(this.txAvg);

  size += encoding.sizeVarint(this.maxConfirms);

  for (let i = 0; i < this.maxConfirms; i++)
    size += sizeArray(this.confAvg[i]);

  return size;
};

/**
 * Serialize confirm stats.
 * @returns {Buffer}
 */

ConfirmStats.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeDouble(this.decay);
  writeArray(bw, this.buckets);
  writeArray(bw, this.avg);
  writeArray(bw, this.txAvg);
  bw.writeVarint(this.maxConfirms);

  for (let i = 0; i < this.maxConfirms; i++)
    writeArray(bw, this.confAvg[i]);

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {ConfirmStats}
 */

ConfirmStats.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let decay = br.readDouble();
  let buckets = readArray(br);
  let avg = readArray(br);
  let txAvg = readArray(br);
  let maxConfirms = br.readVarint();
  let confAvg = new Array(maxConfirms);

  for (let i = 0; i < maxConfirms; i++)
    confAvg[i] = readArray(br);

  if (decay <= 0 || decay >= 1)
    throw new Error('Decay must be between 0 and 1 (non-inclusive).');

  if (buckets.length <= 1 || buckets.length > 1000)
    throw new Error('Must have between 2 and 1000 fee/pri buckets.');

  if (avg.length !== buckets.length)
    throw new Error('Mismatch in fee/pri average bucket count.');

  if (txAvg.length !== buckets.length)
    throw new Error('Mismatch in tx count bucket count.');

  if (maxConfirms <= 0 || maxConfirms > 6 * 24 * 7)
    throw new Error('Must maintain estimates for between 1 and 1008 confirms.');

  for (let i = 0; i < maxConfirms; i++) {
    if (confAvg[i].length !== buckets.length)
      throw new Error('Mismatch in fee/pri conf average bucket count.');
  }

  this.init(buckets, maxConfirms, decay);

  this.avg = avg;
  this.txAvg = txAvg;
  this.confAvg = confAvg;

  return this;
};

/**
 * Instantiate confirm stats from serialized data.
 * @param {Buffer} data
 * @param {String} type
 * @param {Logger?} logger
 * @returns {ConfirmStats}
 */

ConfirmStats.fromRaw = function fromRaw(data, type, logger) {
  return new ConfirmStats(type, logger).fromRaw(data);
};

/**
 * Estimator for fees and priority.
 * @alias module:mempool.PolicyEstimator
 * @constructor
 * @param {Logger?} logger
 */

function PolicyEstimator(logger) {
  if (!(this instanceof PolicyEstimator))
    return new PolicyEstimator(logger);

  this.logger = Logger.global;

  this.minTrackedFee = MIN_FEERATE;
  this.minTrackedPri = MIN_PRIORITY;

  this.feeStats = new ConfirmStats('FeeRate');
  this.priStats = new ConfirmStats('Priority');

  this.feeUnlikely = 0;
  this.feeLikely = INF_FEERATE;
  this.priUnlikely = 0;
  this.priLikely = INF_PRIORITY;

  this.map = new Map();
  this.bestHeight = 0;

  if (policy.MIN_RELAY >= MIN_FEERATE)
    this.minTrackedFee = policy.MIN_RELAY;

  if (policy.FREE_THRESHOLD >= MIN_PRIORITY)
    this.minTrackedPri = policy.FREE_THRESHOLD;

  if (logger) {
    assert(typeof logger === 'object');
    this.logger = logger.context('fees');
    this.feeStats.logger = this.logger;
    this.priStats.logger = this.logger;
  }
}

/**
 * Serialization version.
 * @const {Number}
 * @default
 */

PolicyEstimator.VERSION = 0;

/**
 * Initialize the estimator.
 * @private
 */

PolicyEstimator.prototype.init = function init() {
  let minFee = this.minTrackedFee;
  let minPri = this.minTrackedPri;
  let fee = [];
  let priority = [];

  for (let b = minFee; b <= MAX_FEERATE; b *= FEE_SPACING)
    fee.push(b);

  fee.push(INF_FEERATE);

  for (let b = minPri; b <= MAX_PRIORITY; b *= PRI_SPACING)
    priority.push(b);

  priority.push(INF_PRIORITY);

  this.feeStats.init(fee, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
  this.priStats.init(priority, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
};

/**
 * Reset the estimator.
 */

PolicyEstimator.prototype.reset = function reset() {
  this.feeUnlikely = 0;
  this.feeLikely = INF_FEERATE;
  this.priUnlikely = 0;
  this.priLikely = INF_PRIORITY;

  this.map.clear();
  this.bestHeight = 0;

  this.init();
};

/**
 * Stop tracking a tx. Remove from map.
 * @param {Hash} hash
 */

PolicyEstimator.prototype.removeTX = function removeTX(hash) {
  let item = this.map.get(hash);

  if (!item) {
    this.logger.spam('Mempool tx %s not found.', util.revHex(hash));
    return;
  }

  this.feeStats.removeTX(item.blockHeight, this.bestHeight, item.bucketIndex);

  this.map.delete(hash);
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
  let height = entry.height;
  let hash = entry.hash('hex');
  let fee, rate, priority, item;

  if (this.map.has(hash)) {
    this.logger.debug('Mempool tx %s already tracked.', entry.txid());
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

  this.logger.spam('Processing mempool tx %s.', entry.txid());

  if (fee === 0 || this.isPriPoint(rate, priority)) {
    item = new StatEntry();
    item.blockHeight = height;
    item.bucketIndex = this.priStats.addTX(height, priority);
  } else if (this.isFeePoint(rate, priority)) {
    item = new StatEntry();
    item.blockHeight = height;
    item.bucketIndex = this.feeStats.addTX(height, rate);
  }

  if (!item) {
    this.logger.spam('Not adding tx %s.', entry.txid());
    return;
  }

  this.map.set(hash, item);
};

/**
 * Process an entry being removed from the mempool.
 * @param {Number} height - Block height.
 * @param {MempoolEntry} entry
 */

PolicyEstimator.prototype.processBlockTX = function processBlockTX(height, entry) {
  let blocks, fee, rate, priority;

  // Requires other mempool txs in order to be confirmed. Ignore.
  if (entry.dependencies)
    return;

  blocks = height - entry.height;

  if (blocks <= 0) {
    this.logger.debug(
      'Block tx %s had negative blocks to confirm (%d, %d).',
      entry.txid(),
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
  let entry;

  // Ignore reorgs.
  if (height <= this.bestHeight)
    return;

  this.bestHeight = height;

  if (entries.length === 0)
    return;

  // Wait for chain to sync.
  if (!current)
    return;

  this.logger.debug('Recalculating dynamic cutoffs.');

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

  for (entry of entries)
    this.processBlockTX(height, entry);

  this.feeStats.updateAverages();
  this.priStats.updateAverages();

  this.logger.debug('Done updating estimates'
    + ' for %d confirmed entries. New mempool map size %d.',
    entries.length, this.map.size);

  this.logger.debug('New fee rate: %d.', this.estimateFee());
};

/**
 * Estimate a fee rate.
 * @param {Number} [target=1] - Confirmation target.
 * @param {Boolean} [smart=true] - Smart estimation.
 * @returns {Rate}
 */

PolicyEstimator.prototype.estimateFee = function estimateFee(target, smart) {
  let rate;

  if (!target)
    target = 1;

  if (smart == null)
    smart = true;

  assert(util.isUInt32(target), 'Target must be a number.');
  assert(target <= this.feeStats.maxConfirms,
    'Too many confirmations for estimate.');

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

  if (rate < 0)
    return 0;

  return Math.floor(rate);
};

/**
 * Estimate a priority.
 * @param {Number} [target=1] - Confirmation target.
 * @param {Boolean} [smart=true] - Smart estimation.
 * @returns {Number}
 */

PolicyEstimator.prototype.estimatePriority = function estimatePriority(target, smart) {
  let priority;

  if (!target)
    target = 1;

  if (smart == null)
    smart = true;

  assert(util.isUInt32(target), 'Target must be a number.');
  assert(target <= this.priStats.maxConfirms,
    'Too many confirmations for estimate.');

  if (!smart) {
    priority = this.priStats.estimateMedian(
      target, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
      true, this.bestHeight);
    return Math.floor(priority);
  }

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
 * Get serialization size.
 * @returns {Number}
 */

PolicyEstimator.prototype.getSize = function getSize() {
  let size = 0;
  size += 5;
  size += encoding.sizeVarlen(this.feeStats.getSize());
  return size;
};

/**
 * Serialize the estimator.
 * @returns {Buffer}
 */

PolicyEstimator.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeU8(PolicyEstimator.VERSION);
  bw.writeU32(this.bestHeight);
  bw.writeVarBytes(this.feeStats.toRaw());

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {PolicyEstimator}
 */

PolicyEstimator.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);

  if (br.readU8() !== PolicyEstimator.VERSION)
    throw new Error('Bad serialization version for estimator.');

  this.bestHeight = br.readU32();
  this.feeStats.fromRaw(br.readVarBytes());

  return this;
};

/**
 * Instantiate a policy estimator from serialized data.
 * @param {Buffer} data
 * @param {Logger?} logger
 * @returns {PolicyEstimator}
 */

PolicyEstimator.fromRaw = function fromRaw(data, logger) {
  return new PolicyEstimator(logger).fromRaw(data);
};

/**
 * Inject properties from estimator.
 * @param {PolicyEstimator} estimator
 * @returns {PolicyEstimator}
 */

PolicyEstimator.prototype.inject = function inject(estimator) {
  this.bestHeight = estimator.bestHeight;
  this.feeStats = estimator.feeStats;
  return this;
};

/**
 * StatEntry
 * @alias module:mempool.StatEntry
 * @ignore
 */

function StatEntry() {
  this.blockHeight = -1;
  this.bucketIndex = -1;
}

/**
 * DoubleMap
 * @alias module:mempool.DoubleMap
 * @ignore
 */

function DoubleMap() {
  if (!(this instanceof DoubleMap))
    return new DoubleMap();

  this.buckets = [];
}

DoubleMap.prototype.insert = function insert(key, value) {
  let i = util.binarySearch(this.buckets, key, compare, true);
  this.buckets.splice(i, 0, [key, value]);
};

DoubleMap.prototype.search = function search(key) {
  let i = util.binarySearch(this.buckets, key, compare, true);
  assert(this.buckets.length !== 0, 'Cannot search.');
  return this.buckets[i][1];
};

/*
 * Helpers
 */

function compare(a, b) {
  return a[0] - b;
}

function sizeArray(buckets) {
  let size = encoding.sizeVarint(buckets.length);
  return size + buckets.length * 8;
}

function writeArray(bw, buckets) {
  bw.writeVarint(buckets.length);

  for (let i = 0; i < buckets.length; i++)
    bw.writeDouble(buckets[i]);
}

function readArray(br) {
  let buckets = new Float64Array(br.readVarint());

  for (let i = 0; i < buckets.length; i++)
    buckets[i] = br.readDouble();

  return buckets;
}

/*
 * Expose
 */

exports = PolicyEstimator;
exports.PolicyEstimator = PolicyEstimator;
exports.ConfirmStats = ConfirmStats;

module.exports = exports;
