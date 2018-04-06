/*!
 * fees.js - fee estimation for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Ported from:
 * https://github.com/bitcoin/bitcoin/blob/master/src/policy/fees.cpp
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const Logger = require('blgr');
const util = require('../utils/util');
const binary = require('../utils/binary');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const {encoding} = bio;

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
 */

class ConfirmStats {
  /**
   * Create confirmation stats.
   * @constructor
   * @param {String} type
   * @param {Logger?} logger
   */

  constructor(type, logger) {
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

  init(buckets, maxConfirms, decay) {
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
  }

  /**
   * Clear data for the current block.
   * @param {Number} height
   */

  clearCurrent(height) {
    for (let i = 0; i < this.buckets.length; i++) {
      this.oldUnconfTX[i] = this.unconfTX[height % this.unconfTX.length][i];
      this.unconfTX[height % this.unconfTX.length][i] = 0;
      for (let j = 0; j < this.curBlockConf.length; j++)
        this.curBlockConf[j][i] = 0;
      this.curBlockTX[i] = 0;
      this.curBlockVal[i] = 0;
    }
  }

  /**
   * Record a rate or priority based on number of blocks to confirm.
   * @param {Number} blocks - Blocks to confirm.
   * @param {Rate|Number} val - Rate or priority.
   */

  record(blocks, val) {
    if (blocks < 1)
      return;

    const bucketIndex = this.bucketMap.search(val);

    for (let i = blocks; i <= this.curBlockConf.length; i++)
      this.curBlockConf[i - 1][bucketIndex]++;

    this.curBlockTX[bucketIndex]++;
    this.curBlockVal[bucketIndex] += val;
  }

  /**
   * Update moving averages.
   */

  updateAverages() {
    for (let i = 0; i < this.buckets.length; i++) {
      for (let j = 0; j < this.confAvg.length; j++) {
        this.confAvg[j][i] =
          this.confAvg[j][i] * this.decay + this.curBlockConf[j][i];
      }
      this.avg[i] = this.avg[i] * this.decay + this.curBlockVal[i];
      this.txAvg[i] = this.txAvg[i] * this.decay + this.curBlockTX[i];
    }
  }

  /**
   * Estimate the median value for rate or priority.
   * @param {Number} target - Confirmation target.
   * @param {Number} needed - Sufficient tx value.
   * @param {Number} breakpoint - Success break point.
   * @param {Boolean} greater - Whether to look for lowest value.
   * @param {Number} height - Block height.
   * @returns {Rate|Number} Returns -1 on error.
   */

  estimateMedian(target, needed, breakpoint, greater, height) {
    const max = this.buckets.length - 1;
    const start = greater ? max : 0;
    const step = greater ? -1 : 1;
    const bins = this.unconfTX.length;
    let conf = 0;
    let total = 0;
    let extra = 0;
    let near = start;
    let far = start;
    let bestNear = start;
    let bestFar = start;
    let found = false;
    let median = -1;
    let sum = 0;

    for (let i = start; i >= 0 && i <= max; i += step) {
      far = i;
      conf += this.confAvg[target - 1][i];
      total += this.txAvg[i];

      for (let j = target; j < this.maxConfirms; j++)
        extra += this.unconfTX[Math.max(height - j, 0) % bins][i];

      extra += this.oldUnconfTX[i];

      if (total >= needed / (1 - this.decay)) {
        const perc = conf / (total + extra);

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

    const minBucket = bestNear < bestFar ? bestNear : bestFar;
    const maxBucket = bestNear > bestFar ? bestNear : bestFar;

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
  }

  /**
   * Add a transaction's rate/priority to be tracked.
   * @param {Number} height - Block height.
   * @param {Number} val
   * @returns {Number} Bucket index.
   */

  addTX(height, val) {
    const bucketIndex = this.bucketMap.search(val);
    const blockIndex = height % this.unconfTX.length;
    this.unconfTX[blockIndex][bucketIndex]++;
    this.logger.spam('Adding tx to %s.', this.type);
    return bucketIndex;
  }

  /**
   * Remove a transaction from tracking.
   * @param {Number} entryHeight
   * @param {Number} bestHeight
   * @param {Number} bucketIndex
   */

  removeTX(entryHeight, bestHeight, bucketIndex) {
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
      const blockIndex = entryHeight % this.unconfTX.length;
      if (this.unconfTX[blockIndex][bucketIndex] > 0) {
        this.unconfTX[blockIndex][bucketIndex]--;
      } else {
        this.logger.debug('Mempool tx removed (block=%d, bucket=%d).',
         blockIndex, bucketIndex);
      }
    }
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += 8;

    size += sizeArray(this.buckets);
    size += sizeArray(this.avg);
    size += sizeArray(this.txAvg);

    size += encoding.sizeVarint(this.maxConfirms);

    for (let i = 0; i < this.maxConfirms; i++)
      size += sizeArray(this.confAvg[i]);

    return size;
  }

  /**
   * Serialize confirm stats.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    bw.writeDouble(this.decay);
    writeArray(bw, this.buckets);
    writeArray(bw, this.avg);
    writeArray(bw, this.txAvg);
    bw.writeVarint(this.maxConfirms);

    for (let i = 0; i < this.maxConfirms; i++)
      writeArray(bw, this.confAvg[i]);

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {ConfirmStats}
   */

  fromRaw(data) {
    const br = bio.read(data);
    const decay = br.readDouble();
    const buckets = readArray(br);
    const avg = readArray(br);
    const txAvg = readArray(br);
    const maxConfirms = br.readVarint();
    const confAvg = new Array(maxConfirms);

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
      throw new Error('Must maintain estimates for between 1-1008 confirms.');

    for (let i = 0; i < maxConfirms; i++) {
      if (confAvg[i].length !== buckets.length)
        throw new Error('Mismatch in fee/pri conf average bucket count.');
    }

    this.init(buckets, maxConfirms, decay);

    this.avg = avg;
    this.txAvg = txAvg;
    this.confAvg = confAvg;

    return this;
  }

  /**
   * Instantiate confirm stats from serialized data.
   * @param {Buffer} data
   * @param {String} type
   * @param {Logger?} logger
   * @returns {ConfirmStats}
   */

  static fromRaw(data, type, logger) {
    return new this(type, logger).fromRaw(data);
  }
}

/**
 * Policy Estimator
 * Estimator for fees and priority.
 * @alias module:mempool.PolicyEstimator
 */

class PolicyEstimator {
  /**
   * Create an estimator.
   * @constructor
   * @param {Logger?} logger
   */

  constructor(logger) {
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
   * Initialize the estimator.
   * @private
   */

  init() {
    const minFee = this.minTrackedFee;
    const minPri = this.minTrackedPri;

    const fee = [];

    for (let b = minFee; b <= MAX_FEERATE; b *= FEE_SPACING)
      fee.push(b);

    fee.push(INF_FEERATE);

    const priority = [];

    for (let b = minPri; b <= MAX_PRIORITY; b *= PRI_SPACING)
      priority.push(b);

    priority.push(INF_PRIORITY);

    this.feeStats.init(fee, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
    this.priStats.init(priority, MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
  }

  /**
   * Reset the estimator.
   */

  reset() {
    this.feeUnlikely = 0;
    this.feeLikely = INF_FEERATE;
    this.priUnlikely = 0;
    this.priLikely = INF_PRIORITY;

    this.map.clear();
    this.bestHeight = 0;

    this.init();
  }

  /**
   * Stop tracking a tx. Remove from map.
   * @param {Hash} hash
   */

  removeTX(hash) {
    const item = this.map.get(hash);

    if (!item) {
      this.logger.spam('Mempool tx %s not found.', util.revHex(hash));
      return;
    }

    this.feeStats.removeTX(item.blockHeight, this.bestHeight, item.bucketIndex);

    this.map.delete(hash);
  }

  /**
   * Test whether a fee should be used for calculation.
   * @param {Amount} fee
   * @param {Number} priority
   * @returns {Boolean}
   */

  isFeePoint(fee, priority) {
    if ((priority < this.minTrackedPri && fee >= this.minTrackedFee)
        || (priority < this.priUnlikely && fee > this.feeLikely)) {
      return true;
    }
    return false;
  }

  /**
   * Test whether a priority should be used for calculation.
   * @param {Amount} fee
   * @param {Number} priority
   * @returns {Boolean}
   */

  isPriPoint(fee, priority) {
    if ((fee < this.minTrackedFee && priority >= this.minTrackedPri)
        || (fee < this.feeUnlikely && priority > this.priLikely)) {
      return true;
    }
    return false;
  }

  /**
   * Process a mempool entry.
   * @param {MempoolEntry} entry
   * @param {Boolean} current - Whether the chain is synced.
   */

  processTX(entry, current) {
    const height = entry.height;
    const hash = entry.hash('hex');

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

    const fee = entry.getFee();
    const rate = entry.getRate();
    const priority = entry.getPriority(height);

    this.logger.spam('Processing mempool tx %s.', entry.txid());

    if (fee === 0 || this.isPriPoint(rate, priority)) {
      const item = new StatEntry();
      item.blockHeight = height;
      item.bucketIndex = this.priStats.addTX(height, priority);
      this.map.set(hash, item);
    } else if (this.isFeePoint(rate, priority)) {
      const item = new StatEntry();
      item.blockHeight = height;
      item.bucketIndex = this.feeStats.addTX(height, rate);
      this.map.set(hash, item);
    } else {
      this.logger.spam('Not adding tx %s.', entry.txid());
    }
  }

  /**
   * Process an entry being removed from the mempool.
   * @param {Number} height - Block height.
   * @param {MempoolEntry} entry
   */

  processBlockTX(height, entry) {
    // Requires other mempool txs in order to be confirmed. Ignore.
    if (entry.dependencies)
      return;

    const blocks = height - entry.height;

    if (blocks <= 0) {
      this.logger.debug(
        'Block tx %s had negative blocks to confirm (%d, %d).',
        entry.txid(),
        height,
        entry.height);
      return;
    }

    const fee = entry.getFee();
    const rate = entry.getRate();
    const priority = entry.getPriority(height);

    if (fee === 0 || this.isPriPoint(rate, priority))
      this.priStats.record(blocks, priority);
    else if (this.isFeePoint(rate, priority))
      this.feeStats.record(blocks, rate);
  }

  /**
   * Process a block of transaction entries being removed from the mempool.
   * @param {Number} height - Block height.
   * @param {MempoolEntry[]} entries
   * @param {Boolean} current - Whether the chain is synced.
   */

  processBlock(height, entries, current) {
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

    for (const entry of entries)
      this.processBlockTX(height, entry);

    this.feeStats.updateAverages();
    this.priStats.updateAverages();

    this.logger.debug('Done updating estimates'
      + ' for %d confirmed entries. New mempool map size %d.',
      entries.length, this.map.size);

    this.logger.debug('New fee rate: %d.', this.estimateFee());
  }

  /**
   * Estimate a fee rate.
   * @param {Number} [target=1] - Confirmation target.
   * @param {Boolean} [smart=true] - Smart estimation.
   * @returns {Rate}
   */

  estimateFee(target, smart) {
    if (!target)
      target = 1;

    if (smart == null)
      smart = true;

    assert((target >>> 0) === target, 'Target must be a number.');
    assert(target <= this.feeStats.maxConfirms,
      'Too many confirmations for estimate.');

    if (!smart) {
      const rate = this.feeStats.estimateMedian(
        target, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
        true, this.bestHeight);

      if (rate < 0)
        return 0;

      return Math.floor(rate);
    }

    let rate = -1;
    while (rate < 0 && target <= this.feeStats.maxConfirms) {
      rate = this.feeStats.estimateMedian(
        target++, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
        true, this.bestHeight);
    }

    target -= 1;

    if (rate < 0)
      return 0;

    return Math.floor(rate);
  }

  /**
   * Estimate a priority.
   * @param {Number} [target=1] - Confirmation target.
   * @param {Boolean} [smart=true] - Smart estimation.
   * @returns {Number}
   */

  estimatePriority(target, smart) {
    if (!target)
      target = 1;

    if (smart == null)
      smart = true;

    assert((target >>> 0) === target, 'Target must be a number.');
    assert(target <= this.priStats.maxConfirms,
      'Too many confirmations for estimate.');

    if (!smart) {
      const priority = this.priStats.estimateMedian(
        target, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
        true, this.bestHeight);
      return Math.floor(priority);
    }

    let priority = -1;
    while (priority < 0 && target <= this.priStats.maxConfirms) {
      priority = this.priStats.estimateMedian(
        target++, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
        true, this.bestHeight);
    }

    target -= 1;

    if (priority < 0)
      return 0;

    return Math.floor(priority);
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 5;
    size += encoding.sizeVarlen(this.feeStats.getSize());
    return size;
  }

  /**
   * Serialize the estimator.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    bw.writeU8(PolicyEstimator.VERSION);
    bw.writeU32(this.bestHeight);
    bw.writeVarBytes(this.feeStats.toRaw());

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {PolicyEstimator}
   */

  fromRaw(data) {
    const br = bio.read(data);

    if (br.readU8() !== PolicyEstimator.VERSION)
      throw new Error('Bad serialization version for estimator.');

    this.bestHeight = br.readU32();
    this.feeStats.fromRaw(br.readVarBytes());

    return this;
  }

  /**
   * Instantiate a policy estimator from serialized data.
   * @param {Buffer} data
   * @param {Logger?} logger
   * @returns {PolicyEstimator}
   */

  static fromRaw(data, logger) {
    return new this(logger).fromRaw(data);
  }

  /**
   * Inject properties from estimator.
   * @param {PolicyEstimator} estimator
   * @returns {PolicyEstimator}
   */

  inject(estimator) {
    this.bestHeight = estimator.bestHeight;
    this.feeStats = estimator.feeStats;
    return this;
  }
}

/**
 * Serialization version.
 * @const {Number}
 * @default
 */

PolicyEstimator.VERSION = 0;

/**
 * Stat Entry
 * @alias module:mempool.StatEntry
 * @ignore
 */

class StatEntry {
  /**
   * StatEntry
   * @constructor
   */

  constructor() {
    this.blockHeight = -1;
    this.bucketIndex = -1;
  }
}

/**
 * Double Map
 * @alias module:mempool.DoubleMap
 * @ignore
 */

class DoubleMap {
  /**
   * DoubleMap
   * @constructor
   */

  constructor() {
    this.buckets = [];
  }

  insert(key, value) {
    const i = binary.search(this.buckets, key, compare, true);
    this.buckets.splice(i, 0, [key, value]);
  }

  search(key) {
    assert(this.buckets.length !== 0, 'Cannot search.');
    const i = binary.search(this.buckets, key, compare, true);
    return this.buckets[i][1];
  }
}

/*
 * Helpers
 */

function compare(a, b) {
  return a[0] - b;
}

function sizeArray(buckets) {
  const size = encoding.sizeVarint(buckets.length);
  return size + buckets.length * 8;
}

function writeArray(bw, buckets) {
  bw.writeVarint(buckets.length);

  for (let i = 0; i < buckets.length; i++)
    bw.writeDouble(buckets[i]);
}

function readArray(br) {
  const buckets = new Float64Array(br.readVarint());

  for (let i = 0; i < buckets.length; i++)
    buckets[i] = br.readDouble();

  return buckets;
}

/*
 * Expose
 */

module.exports = PolicyEstimator;
