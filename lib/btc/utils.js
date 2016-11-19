/*!
 * utils.js - bitcoin-related utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var Amount = require('./amount');
var utils = exports;

/**
 * Convert a compact number to a big number.
 * Used for `block.bits` -> `target` conversion.
 * @param {Number} compact
 * @returns {BN}
 */

utils.fromCompact = function fromCompact(compact) {
  var exponent = compact >>> 24;
  var negative = (compact >>> 23) & 1;
  var mantissa = compact & 0x7fffff;
  var num;

  if (compact === 0)
    return new BN(0);

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa >>>= 8 * (3 - exponent);
    num = new BN(mantissa);
  } else {
    num = new BN(mantissa);
    num.iushln(8 * (exponent - 3));
  }

  if (negative)
    num.ineg();

  return num;
};

/**
 * Convert a big number to a compact number.
 * Used for `target` -> `block.bits` conversion.
 * @param {BN} num
 * @returns {Number}
 */

utils.toCompact = function toCompact(num) {
  var mantissa, exponent, compact;

  if (num.cmpn(0) === 0)
    return 0;

  exponent = num.byteLength();

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa = num.toNumber();
    mantissa <<= 8 * (3 - exponent);
  } else {
    mantissa = num.ushrn(8 * (exponent - 3)).toNumber();
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent++;
  }

  compact = (exponent << 24) | mantissa;

  if (num.isNeg())
    compact |= 0x800000;

  compact >>>= 0;

  return compact;
};

/**
 * Verify proof-of-work.
 * @returns {Boolean}
 */

utils.verifyPOW = function verifyPOW(hash, bits) {
  var target = utils.fromCompact(bits);

  if (target.isNeg() || target.cmpn(0) === 0)
    return false;

  hash = new BN(hash, 'le');

  if (hash.cmp(target) > 0)
    return false;

  return true;
};

/**
 * Calculate block subsidy.
 * @param {Number} height - Reward era by height.
 * @returns {Amount}
 */

utils.getReward = function getReward(height, interval) {
  var halvings = Math.floor(height / interval);

  assert(height >= 0, 'Bad height for reward.');

  // BIP 42 (well, our own version of it,
  // since we can only handle 32 bit shifts).
  // https://github.com/bitcoin/bips/blob/master/bip-0042.mediawiki
  if (halvings >= 33)
    return 0;

  // We need to shift right by `halvings`,
  // but 50 btc is a 33 bit number, so we
  // cheat. We only start halving once the
  // halvings are at least 1.
  if (halvings === 0)
    return 5000000000;

  return 2500000000 >>> (halvings - 1);
};

/**
 * Calculate minimum fee based on rate and size.
 * @param {Number?} size
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

utils.getMinFee = function getMinFee(size, rate) {
  var fee;

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  fee = Math.floor(rate * size / 1000);

  if (fee === 0 && rate > 0)
    fee = rate;

  return fee;
};

/**
 * Calculate the minimum fee in order for the transaction
 * to be relayable, but _round to the nearest kilobyte
 * when taking into account size.
 * @param {Number?} size
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

utils.getRoundFee = function getRoundFee(size, rate) {
  var fee;

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  fee = rate * Math.ceil(size / 1000);

  if (fee === 0 && rate > 0)
    fee = rate;

  return fee;
};

/**
 * Calculate a fee rate based on size and fees.
 * @param {Number} size
 * @param {Amount} fee
 * @returns {Rate}
 */

utils.getRate = function getRate(size, fee) {
  return Math.floor(fee * 1000 / size);
};

/**
 * Safely convert satoshis to a BTC string.
 * This function explicitly avoids any
 * floating point arithmetic.
 * @param {Amount} value - Satoshis.
 * @returns {String} BTC string.
 */

utils.btc = function btc(value) {
  if (util.isFloat(value))
    return value;
  return Amount.fromValue(value).toBTC();
};

/**
 * Safely convert a BTC string to satoshis.
 * This function explicitly avoids any
 * floating point arithmetic. It also does
 * extra validation to ensure the resulting
 * Number will be 53 bits or less.
 * @param {String} value - BTC
 * @returns {Amount} Satoshis.
 * @throws on parse error
 */

utils.satoshi = function satoshi(value) {
  if (util.isInt(value))
    return value;
  return Amount.fromBTC(value).toValue();
};

/**
 * Test and validate a satoshi value (Number).
 * @param {Number?} value
 * @returns {Boolean}
 */

utils.isSatoshi = function isSatoshi(value) {
  try {
    Amount.fromValue(value);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Test and validate a BTC string.
 * @param {String?} value
 * @returns {Boolean}
 */

utils.isBTC = function isBTC(value) {
  try {
    Amount.fromBTC(value);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Sort an array of transactions in dependency order.
 * @param {TX[]} txs
 * @returns {TX[]}
 */

utils.sortTX = function sortTX(txs) {
  var depMap = {};
  var count = {};
  var result = [];
  var top = [];
  var map = txs;
  var i, j, tx, hash, input;
  var prev, hasDeps, deps;

  if (Array.isArray(txs)) {
    map = {};
    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      hash = tx.hash('hex');
      map[hash] = tx;
    }
  }

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');
    hasDeps = false;

    count[hash] = 0;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!map[prev])
        continue;

      count[hash] += 1;
      hasDeps = true;

      if (!depMap[prev])
        depMap[prev] = [];

      depMap[prev].push(tx);
    }

    if (hasDeps)
      continue;

    top.push(tx);
  }

  for (i = 0; i < top.length; i++) {
    tx = top[i];
    hash = tx.hash('hex');

    result.push(tx);

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      tx = deps[j];
      hash = tx.hash('hex');

      if (--count[hash] === 0)
        top.push(tx);
    }
  }

  return result;
};
