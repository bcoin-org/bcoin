/*!
 * common.js - p2p constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/common
 */

const pkg = require('../pkg');

/**
 * Default protocol version.
 * @const {Number}
 * @default
 */

exports.PROTOCOL_VERSION = 70015;

/**
 * Minimum protocol version we're willing to talk to.
 * @const {Number}
 * @default
 */

exports.MIN_VERSION = 70001;

/**
 * Minimum version for getheaders.
 * @const {Number}
 * @default
 */

exports.HEADERS_VERSION = 31800;

/**
 * Minimum version for pong.
 * @const {Number}
 * @default
 */

exports.PONG_VERSION = 60000;

/**
 * Minimum version for bip37.
 * @const {Number}
 * @default
 */

exports.BLOOM_VERSION = 70011;

/**
 * Minimum version for bip152.
 * @const {Number}
 * @default
 */

exports.SENDHEADERS_VERSION = 7012;

/**
 * Minimum version for bip152.
 * @const {Number}
 * @default
 */

exports.COMPACT_VERSION = 70014;

/**
 * Minimum version for bip152+segwit.
 * @const {Number}
 * @default
 */

exports.COMPACT_WITNESS_VERSION = 70015;

/**
 * Service bits.
 * @enum {Number}
 * @default
 */

exports.services = {
  /**
   * Whether network services are enabled.
   */

  NETWORK: 1 << 0,

  /**
   * Whether the peer supports the getutxos packet.
   */

  GETUTXO: 1 << 1,

  /**
   * Whether the peer supports BIP37.
   */

  BLOOM: 1 << 2,

  /**
   * Whether the peer supports segregated witness.
   */

  WITNESS: 1 << 3
};

/**
 * Bcoin's services (we support everything).
 * @const {Number}
 * @default
 */

exports.LOCAL_SERVICES = 0
  | exports.services.NETWORK
  | exports.services.WITNESS;

/**
 * Required services (network and segwit).
 * @const {Number}
 * @default
 */

exports.REQUIRED_SERVICES = 0
  | exports.services.NETWORK;

/**
 * Default user agent: `/bcoin:[version]/`.
 * @const {String}
 * @default
 */

exports.USER_AGENT = `/bcoin:${pkg.version}/`;

/**
 * Max message size (~4mb with segwit, formerly 2mb)
 * @const {Number}
 * @default
 */

exports.MAX_MESSAGE = 4 * 1000 * 1000;

/**
 * Amount of time to ban misbheaving peers.
 * @const {Number}
 * @default
 */

exports.BAN_TIME = 24 * 60 * 60;

/**
 * Ban score threshold before ban is placed in effect.
 * @const {Number}
 * @default
 */

exports.BAN_SCORE = 100;

/**
 * Create a nonce.
 * @returns {Buffer}
 */

exports.nonce = function nonce() {
  const data = Buffer.allocUnsafe(8);
  data.writeUInt32LE(Math.random() * 0x100000000, true, 0);
  data.writeUInt32LE(Math.random() * 0x100000000, true, 4);
  return data;
};

/**
 * A compressed pubkey of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_KEY = Buffer.alloc(33, 0x00);

/**
 * A 64 byte signature of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_SIG = Buffer.alloc(64, 0x00);

/**
 * 8 zero bytes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_NONCE = Buffer.alloc(8, 0x00);
