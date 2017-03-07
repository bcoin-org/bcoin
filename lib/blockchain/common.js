/*!
 * common.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module blockchain/common
 */

/**
 * Locktime flags.
 * @enum {Number}
 */

exports.lockFlags = {
  VERIFY_SEQUENCE: 1 << 0,
  MEDIAN_TIME_PAST: 1 << 1
};

/**
 * Consensus locktime flags (used for block validation).
 * @const {LockFlags}
 * @default
 */

exports.lockFlags.MANDATORY_LOCKTIME_FLAGS = 0;

/**
 * Standard locktime flags (used for mempool validation).
 * @const {LockFlags}
 * @default
 */

exports.lockFlags.STANDARD_LOCKTIME_FLAGS = 0
  | exports.lockFlags.VERIFY_SEQUENCE
  | exports.lockFlags.MEDIAN_TIME_PAST;

/**
 * Threshold states for versionbits
 * @enum {Number}
 * @default
 */

exports.thresholdStates = {
  DEFINED: 0,
  STARTED: 1,
  LOCKED_IN: 2,
  ACTIVE: 3,
  FAILED: 4
};

/**
 * Verify flags for blocks.
 * @enum {Number}
 * @default
 */

exports.flags = {
  VERIFY_NONE: 0,
  VERIFY_POW: 1 << 0,
  VERIFY_BODY: 1 << 1
};

/**
 * Default block verify flags.
 * @const {Number}
 * @default
 */

exports.flags.DEFAULT_FLAGS = 0
  | exports.flags.VERIFY_POW
  | exports.flags.VERIFY_BODY;
