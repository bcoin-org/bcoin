/*!
 * policy.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var consensus = require('./consensus');

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

exports.MAX_SCRIPTHASH_SIGOPS = 15;

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
 * Mempool ancestor limit.
 * @const {Number}
 * @default
 */

exports.ANCESTOR_LIMIT = 25;

/**
 * Block weight to be reached before
 * rejecting free transactions during
 * mining.
 * @const {Number}
 * @default
 */

exports.MIN_BLOCK_WEIGHT = 0;

/**
 * Maximum block weight to be mined.
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_WEIGHT = 750000 * consensus.WITNESS_SCALE_FACTOR;

/**
 * Bottom priority threshold to be seen
 * before ignoring priority transactions
 * during mining.
 * @const {Number}
 * @default
 */

exports.MIN_BLOCK_PRIORITY = 50000 * consensus.WITNESS_SCALE_FACTOR;

/**
 * Weight to be reached before ignoring
 * priority transactions during mining.
 * @const {Number}
 * @default
 */

exports.PRIORITY_BLOCK_WEIGHT = exports.FREE_THRESHOLD;

/**
 * Calculate minimum fee based on rate and size.
 * @param {Number?} size
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

exports.getMinFee = function getMinFee(size, rate) {
  var fee;

  if (rate == null)
    rate = exports.MIN_RELAY;

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

exports.getRoundFee = function getRoundFee(size, rate) {
  var fee;

  if (rate == null)
    rate = exports.MIN_RELAY;

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

exports.getRate = function getRate(size, fee) {
  return Math.floor(fee * 1000 / size);
};
