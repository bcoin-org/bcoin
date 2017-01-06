/*!
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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
 * Versionbits constants.
 * @enum {Number}
 * @default
 */

exports.versionbits = {
  /**
   * What block version to use for new blocks (pre versionbits)
   */

  LAST_OLD_BLOCK_VERSION: 4,

  /**
   * What bits to set in version for versionbits blocks
   */

  TOP_BITS: 0x20000000,

  /**
   * What bitmask determines whether versionbits is in use
   */

  TOP_MASK: 0xe0000000
};

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
