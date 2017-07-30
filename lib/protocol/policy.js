/*!
 * policy.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module protocol/policy
 */

const assert = require('assert');
const consensus = require('./consensus');

/**
 * Maximum transaction version (policy).
 * @const {Number}
 * @default
 */

exports.MAX_TX_VERSION = 2;

/**
 * Maximum transaction base size (policy).
 * @const {Number}
 * @default
 */

exports.MAX_TX_SIZE = consensus.MAX_BLOCK_SIZE / 10;

/**
 * Maximum transaction weight (policy).
 * @const {Number}
 * @default
 */

exports.MAX_TX_WEIGHT = consensus.MAX_BLOCK_WEIGHT / 10;

/**
 * Maximum number of transaction sigops (policy).
 * @const {Number}
 * @default
 */

exports.MAX_TX_SIGOPS = consensus.MAX_BLOCK_SIGOPS / 5;

/**
 * Maximum cost of transaction sigops (policy).
 * @const {Number}
 * @default
 */

exports.MAX_TX_SIGOPS_COST = consensus.MAX_BLOCK_SIGOPS_COST / 5;

/**
 * How much weight a sigop should
 * add to virtual size (policy).
 * @const {Number}
 * @default
 */

exports.BYTES_PER_SIGOP = 20;

/**
 * Minimum relay fee rate (policy).
 * @const {Rate}
 */

exports.MIN_RELAY = 1000;

/**
 * Whether bare multisig outputs
 * should be relayed (policy).
 * @const {Boolean}
 * @default
 */

exports.BARE_MULTISIG = true;

/**
 * Priority threshold for
 * free transactions (policy).
 * @const {Number}
 * @default
 */

exports.FREE_THRESHOLD = consensus.COIN * 144 / 250;

/**
 * Max sigops per redeem script (policy).
 * @const {Number}
 * @default
 */

exports.MAX_P2SH_SIGOPS = 15;

/**
 * Max serialized nulldata size (policy).
 * @const {Number}
 * @default
 */

exports.MAX_OP_RETURN_BYTES = 83;

/**
 * Max pushdata size in nulldata (policy).
 * @const {Number}
 * @default
 */

exports.MAX_OP_RETURN = 80;

/**
 * Max p2wsh stack size. Used for
 * witness malleation checks (policy).
 * @const {Number}
 * @default
 */

exports.MAX_P2WSH_STACK = 100;

/**
 * Max p2wsh push size. Used for
 * witness malleation checks (policy).
 * @const {Number}
 * @default
 */

exports.MAX_P2WSH_PUSH = 80;

/**
 * Max serialized p2wsh size. Used for
 * witness malleation checks (policy).
 * @const {Number}
 * @default
 */

exports.MAX_P2WSH_SIZE = 3600;

/**
 * Default ancestor limit.
 * @const {Number}
 * @default
 */

exports.MEMPOOL_MAX_ANCESTORS = 25;

/**
 * Default maximum mempool size in bytes.
 * @const {Number}
 * @default
 */

exports.MEMPOOL_MAX_SIZE = 100 * 1000000;

/**
 * Time at which transactions
 * fall out of the mempool.
 * @const {Number}
 * @default
 */

exports.MEMPOOL_EXPIRY_TIME = 72 * 60 * 60;

/**
 * Maximum number of orphan transactions.
 * @const {Number}
 * @default
 */

exports.MEMPOOL_MAX_ORPHANS = 100;

/**
 * Minimum block size to create. Block will be
 * filled with free transactions until block
 * reaches this weight.
 * @const {Number}
 * @default
 */

exports.MIN_BLOCK_WEIGHT = 0;

/**
 * Maximum block weight to be mined.
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_WEIGHT = 1000000 * consensus.WITNESS_SCALE_FACTOR;

/**
 * How much of the block should be dedicated to
 * high-priority transactions (included regardless
 * of fee rate).
 * @const {Number}
 * @default
 */

exports.BLOCK_PRIORITY_WEIGHT = 0;

/**
 * Priority threshold to be reached before
 * switching to fee rate comparison.
 * @const {Number}
 * @default
 */

exports.BLOCK_PRIORITY_THRESHOLD = exports.FREE_THRESHOLD;

/**
 * Calculate minimum fee based on rate and size.
 * @param {Number?} size
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

exports.getMinFee = function getMinFee(size, rate) {
  if (rate == null)
    rate = exports.MIN_RELAY;

  assert(size >= 0);
  assert(rate >= 0);

  if (size === 0)
    return 0;

  let fee = Math.floor(rate * size / 1000);

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

exports.getRoundFee = function getRoundFee(size, rate) {
  if (rate == null)
    rate = exports.MIN_RELAY;

  assert(size >= 0);
  assert(rate >= 0);

  if (size === 0)
    return 0;

  let fee = rate * Math.ceil(size / 1000);

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

exports.getRate = function getRate(size, fee) {
  assert(size >= 0);
  assert(fee >= 0);

  if (size === 0)
    return 0;

  return Math.floor(fee * 1000 / size);
};
