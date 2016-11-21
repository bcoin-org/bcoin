/*!
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module constants
 */

var util = require('../utils/util');

/**
 * Minimum protocol version we're willing to talk to.
 * @const {Number}
 * @default
 */

exports.MIN_VERSION = 70001;

/**
 * BCoin's protocol version.
 * @const {Number}
 * @default
 */

exports.VERSION = 70014;

/**
 * Max message size (~4mb with segwit, formerly 2mb)
 * @const {Number}
 * @default
 */

exports.MAX_MESSAGE = 4 * 1000 * 1000;

/**
 * Service bits.
 * @enum {Number}
 * @default
 */

exports.services = {
  /**
   * Whether network services are enabled.
   */

  NETWORK: (1 << 0),

  /**
   * Whether the peer supports the getutxos packet.
   */

  GETUTXO: (1 << 1),

  /**
   * Whether the peer supports BIP37.
   */

  BLOOM: (1 << 2),

  /**
   * Whether the peer supports segregated witness.
   */

  WITNESS: (1 << 3)
};

/**
 * BCoin's services (we support everything).
 * @const {Number}
 * @default
 */

exports.LOCAL_SERVICES = 0
  | exports.services.NETWORK
  | exports.services.GETUTXO
  | exports.services.BLOOM
  | exports.services.WITNESS;

/**
 * Inv types.
 * @enum {Number}
 * @default
 */

exports.inv = {
  ERROR: 0,
  TX: 1,
  BLOCK: 2,
  FILTERED_BLOCK: 3,
  WITNESS_TX: 1 | (1 << 30),
  WITNESS_BLOCK: 2 | (1 << 30),
  WITNESS_FILTERED_BLOCK: 3 | (1 << 30),
  CMPCT_BLOCK: 4
};

/**
 * Inv types by value.
 * @const {RevMap}
 */

exports.invByVal = util.revMap(exports.inv);

/**
 * Witness mask for inv types.
 * @const {Number}
 * @default
 */

exports.WITNESS_MASK = 1 << 30;

/**
 * Bloom filter update flags.
 * @enum {Number}
 * @default
 */

exports.filterFlags = {
  /**
   * Never update the filter with outpoints.
   */

  NONE: 0,

  /**
   * Always update the filter with outpoints.
   */

  ALL: 1,

  /**
   * Only update the filter with outpoints if it is
   * "asymmetric" in terms of addresses (pubkey/multisig).
   */

  PUBKEY_ONLY: 2
};

/**
 * Bloom filter limits.
 * @enum {Number}
 * @default
 */

exports.bloom = {
  MAX_BLOOM_FILTER_SIZE: 36000,
  MAX_HASH_FUNCS: 50
};

/**
 * Bloom filter update flags by value.
 * @const {RevMap}
 */

exports.filterFlagsByVal = util.revMap(exports.filterFlags);

/**
 * Script opcodes.
 * @enum {Number}
 * @default
 */

exports.opcodes = {
  OP_FALSE: 0x00,
  OP_0: 0x00,

  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,

  OP_1NEGATE: 0x4f,

  OP_RESERVED: 0x50,

  OP_TRUE: 0x51,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_8: 0x58,
  OP_9: 0x59,
  OP_10: 0x5a,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_13: 0x5d,
  OP_14: 0x5e,
  OP_15: 0x5f,
  OP_16: 0x60,

  OP_NOP: 0x61,
  OP_VER: 0x62,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_VERIF: 0x65,
  OP_VERNOTIF: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_RETURN: 0x6a,

  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
  OP_3DUP: 0x6f,
  OP_2OVER: 0x70,
  OP_2ROT: 0x71,
  OP_2SWAP: 0x72,
  OP_IFDUP: 0x73,
  OP_DEPTH: 0x74,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_OVER: 0x78,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_ROT: 0x7b,
  OP_SWAP: 0x7c,
  OP_TUCK: 0x7d,

  OP_CAT: 0x7e,
  OP_SUBSTR: 0x7f,
  OP_LEFT: 0x80,
  OP_RIGHT: 0x81,
  OP_SIZE: 0x82,

  OP_INVERT: 0x83,
  OP_AND: 0x84,
  OP_OR: 0x85,
  OP_XOR: 0x86,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,

  OP_RESERVED1: 0x89,
  OP_RESERVED2: 0x8a,

  OP_1ADD: 0x8b,
  OP_1SUB: 0x8c,
  OP_2MUL: 0x8d,
  OP_2DIV: 0x8e,
  OP_NEGATE: 0x8f,
  OP_ABS: 0x90,
  OP_NOT: 0x91,
  OP_0NOTEQUAL: 0x92,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_LSHIFT: 0x98,
  OP_RSHIFT: 0x99,
  OP_BOOLAND: 0x9a,
  OP_BOOLOR: 0x9b,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_NUMNOTEQUAL: 0x9e,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHAN: 0xa0,
  OP_LESSTHANOREQUAL: 0xa1,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_MIN: 0xa3,
  OP_MAX: 0xa4,
  OP_WITHIN: 0xa5,

  OP_RIPEMD160: 0xa6,
  OP_SHA1: 0xa7,
  OP_SHA256: 0xa8,
  OP_HASH160: 0xa9,
  OP_HASH256: 0xaa,
  OP_CODESEPARATOR: 0xab,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKMULTISIGVERIFY: 0xaf,

  OP_EVAL: 0xb0,
  OP_NOP1: 0xb0,
  OP_NOP2: 0xb1,
  OP_CHECKLOCKTIMEVERIFY: 0xb1,
  OP_NOP3: 0xb2,
  OP_CHECKSEQUENCEVERIFY: 0xb2,
  OP_NOP4: 0xb3,
  OP_NOP5: 0xb4,
  OP_NOP6: 0xb5,
  OP_NOP7: 0xb6,
  OP_NOP8: 0xb7,
  OP_NOP9: 0xb8,
  OP_NOP10: 0xb9,

  OP_PUBKEYHASH: 0xfd,
  OP_PUBKEY: 0xfe,
  OP_INVALIDOPCODE: 0xff
};

/**
 * Opcodes by value.
 * @const {RevMap}
 */

exports.opcodesByVal = util.revMap(exports.opcodes);

/**
 * One bitcoin in satoshis.
 * @const {Amount}
 * @default
 */

exports.COIN = 100000000;

/**
 * One bitcoin / 100.
 * @const {Amount}
 * @default
 */

exports.CENT = 1000000;

/**
 * Maximum amount of money in satoshis (1btc * 21million)
 * @const {Amount}
 * @default
 */

exports.MAX_MONEY = 21000000 * exports.COIN;

/**
 * Sighash Types.
 * @enum {SighashType}
 * @default
 */

exports.hashType = {
  /**
   * Sign all outputs.
   */

  ALL: 1,

  /**
   * Do not sign outputs (zero sequences).
   */

  NONE: 2,

  /**
   * Sign output at the same index (zero sequences).
   */

  SINGLE: 3,

  /**
   * Sign only the current input (mask).
   */

  ANYONECANPAY: 0x80
};

/**
 * Sighash types by value.
 * @const {RevMap}
 */

exports.hashTypeByVal = util.revMap(exports.hashType);

/**
 * Amount to multiply base/non-witness sizes by.
 * @const {Number}
 * @default
 */

exports.WITNESS_SCALE_FACTOR = 4;

/**
 * Block-related constants.
 * @enum {Number}
 * @default
 */

exports.block = {
  MAX_SIZE: 1000000,
  MAX_WEIGHT: 4000000,
  MAX_SIGOPS: 1000000 / 50,
  MAX_SIGOPS_WEIGHT: 80000,
  MEDIAN_TIMESPAN: 11,
  BIP16_TIME: 1333238400,
  SIGHASH_LIMIT: 1300000000
};

/**
 * Map of historical blocks which create duplicate transactions hashes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
 * @const {Object}
 * @default
 */

exports.bip30 = {
  91842: 'eccae000e3c8e4e093936360431f3b7603c563c1ff6181390a4d0a0000000000',
  91880: '21d77ccb4c08386a04ac0196ae10f6a1d2c2a377558ca190f143070000000000'
};

/**
 * TX-related constants.
 * @enum {Number}
 * @default
 */

exports.tx = {
  MAX_VERSION: 2,
  MAX_SIZE: 100000,
  MAX_WEIGHT: 400000,
  MIN_FEE: 10000,
  MAX_FEE: exports.COIN / 10,
  MIN_RELAY: 10000,
  BARE_MULTISIG: true,
  FREE_THRESHOLD: exports.COIN * 144 / 250,
  MAX_SIGOPS: exports.block.MAX_SIGOPS / 5,
  MAX_SIGOPS_WEIGHT: exports.block.MAX_SIGOPS_WEIGHT / 5,
  COINBASE_MATURITY: 100
};

exports.tx.DUST_THRESHOLD = 182 * exports.tx.MIN_RELAY / 1000 * 3;

/**
 * Script-related constants.
 * @enum {Number}
 * @default
 */

exports.script = {
  MAX_SIZE: 10000,
  MAX_STACK: 1000,
  MAX_PUSH: 520,
  MAX_OPS: 201,
  MAX_MULTISIG_PUBKEYS: 20,
  MAX_SCRIPTHASH_SIGOPS: 15,
  MAX_OP_RETURN_BYTES: 83,
  MAX_OP_RETURN: 80,
  BYTES_PER_SIGOP: 20,
  MAX_P2WSH_STACK: 100,
  MAX_P2WSH_PUSH: 80,
  MAX_P2WSH_SIZE: 3600
};

/**
 * Mempool-related constants.
 * @enum {Number}
 * @default
 */

exports.mempool = {
  /**
   * Ancestor limit.
   */

  ANCESTOR_LIMIT: 25,

  /**
   * Maximum mempool size in bytes.
   */

  MAX_MEMPOOL_SIZE: 100 * 1000000,

  /**
   * The time at which transactions
   * fall out of the mempool.
   */

  MEMPOOL_EXPIRY: 72 * 60 * 60,

  /**
   * Maximum number of orphan transactions.
   */

  MAX_ORPHAN_TX: 100,

  /**
   * Decay of minimum fee rate.
   */

  FEE_HALFLIFE: 60 * 60 * 12
};

/**
 * Reject codes. Note that `internal` and higher
 * are not meant for use on the p2p network.
 * @enum {Number}
 * @default
 */

exports.reject = {
  MALFORMED: 0x01,
  INVALID: 0x10,
  OBSOLETE: 0x11,
  DUPLICATE: 0x12,
  NONSTANDARD: 0x40,
  DUST: 0x41,
  INSUFFICIENTFEE: 0x42,
  CHECKPOINT: 0x43,
  // Internal codes (NOT FOR USE ON NETWORK)
  INTERNAL: 0x100,
  HIGHFEE: 0x100,
  ALREADYKNOWN: 0x101,
  CONFLICT: 0x102
};

/**
 * Reject codes by value.
 * @const {RevMap}
 */

exports.rejectByVal = util.revMap(exports.reject);

/**
 * HD-related constants.
 * @const {Object}
 * @default
 */

exports.hd = {
  HARDENED: 0x80000000,
  MAX_INDEX: 0x100000000,
  MIN_ENTROPY: 128,
  MAX_ENTROPY: 512
};

/**
 * nLockTime threshold for differentiating
 * between height and time.
 * Tue Nov 5 00:53:20 1985 UTC
 * @const {Number}
 * @default
 */

exports.LOCKTIME_THRESHOLD = 500000000;

/**
 * Sequence locktime-related constants.
 * @enum {Number}
 * @default
 */

exports.sequence = {
  /**
   * Highest nSequence bit (disables sequence locktimes).
   */

  DISABLE_FLAG: (1 << 31) >>> 0,

  /**
   * Type (height or time).
   */

  TYPE_FLAG: 1 << 22,

  /**
   * Sequence granularity.
   */

  GRANULARITY: 9,

  /**
   * Mask.
   */

  MASK: 0x0000ffff
};

/**
 * A hash of all zeroes with a `1` at the
 * end (used for the SIGHASH_SINGLE bug).
 * @const {Buffer}
 * @default
 */

exports.ONE_HASH = new Buffer(
  '0100000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

/**
 * A hash of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_HASH = new Buffer(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

/**
 * A hash of all 0xff.
 * @const {Buffer}
 * @default
 */

exports.MAX_HASH = new Buffer(
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);

/**
 * A hash of all zeroes.
 * @const {String}
 * @default
 */

exports.NULL_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * A hash of all 0xff.
 * @const {String}
 * @default
 */

exports.HIGH_HASH =
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

/**
 * A hash of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_HASH160 = new Buffer(
  '0000000000000000000000000000000000000000',
  'hex'
);

/**
 * A hash of all 0xff.
 * @const {String}
 * @default
 */

exports.MAX_HASH160 = new Buffer(
  'ffffffffffffffffffffffffffffffffffffffff',
  'hex'
);

/**
 * A hash of all zeroes.
 * @const {String}
 * @default
 */

exports.NULL_HASH160 = '0000000000000000000000000000000000000000';

/**
 * A hash of all 0xff.
 * @const {String}
 * @default
 */

exports.HIGH_HASH160 = 'ffffffffffffffffffffffffffffffffffffffff';

/**
 * A compressed pubkey of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_KEY = new Buffer(
  '000000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

/**
 * A 73 byte signature of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_SIG = new Buffer(''
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '000000000000000000',
  'hex'
);

/**
 * A 64 byte signature of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_SIG64 = new Buffer(''
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

/**
 * 4 zero bytes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_U32 = new Buffer('00000000', 'hex');

/**
 * 8 zero bytes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_U64 = new Buffer('0000000000000000', 'hex');

/**
 * BCoin version.
 * @const {String}
 * @default
 */

exports.USER_VERSION = require('../../package.json').version;

/**
 * BCoin user agent: `/bcoin:{version}/`.
 * @const {String}
 * @default
 */

exports.USER_AGENT = '/bcoin:' + exports.USER_VERSION + '/';

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
 * Output script types.
 * @enum {Number}
 */

exports.scriptTypes = {
  NONSTANDARD: 0,
  PUBKEY: 1,
  PUBKEYHASH: 2,
  SCRIPTHASH: 3,
  MULTISIG: 4,
  NULLDATA: 5,
  WITNESSMALFORMED: 0x80 | 0,
  WITNESSSCRIPTHASH: 0x80 | 1,
  WITNESSPUBKEYHASH: 0x80 | 2,
  WITNESSMASTHASH: 0x80 | 3
};

/**
 * Output script types by value.
 * @const {RevMap}
 */

exports.scriptTypesByVal = util.revMap(exports.scriptTypes);

/**
 * Script and locktime flags. See {@link VerifyFlags}.
 * @enum {Number}
 */

exports.flags = {
  VERIFY_NONE: 0,
  VERIFY_P2SH: (1 << 0),
  VERIFY_STRICTENC: (1 << 1),
  VERIFY_DERSIG: (1 << 2),
  VERIFY_LOW_S: (1 << 3),
  VERIFY_NULLDUMMY: (1 << 4),
  VERIFY_SIGPUSHONLY: (1 << 5),
  VERIFY_MINIMALDATA: (1 << 6),
  VERIFY_DISCOURAGE_UPGRADABLE_NOPS: (1 << 7),
  VERIFY_CLEANSTACK: (1 << 8),
  VERIFY_CHECKLOCKTIMEVERIFY: (1 << 9),
  VERIFY_CHECKSEQUENCEVERIFY: (1 << 10),
  VERIFY_WITNESS: (1 << 11),
  VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: (1 << 12),
  VERIFY_MINIMALIF: (1 << 13),
  VERIFY_NULLFAIL: (1 << 14),
  VERIFY_WITNESS_PUBKEYTYPE: (1 << 15),
  VERIFY_MAST: (1 << 16), // should be 1 << 13
  VERIFY_SEQUENCE: (1 << 0),
  MEDIAN_TIME_PAST: (1 << 1)
};

/**
 * Consensus verify flags (used for block validation).
 * @const {VerifyFlags}
 * @default
 */

exports.flags.MANDATORY_VERIFY_FLAGS = exports.flags.VERIFY_P2SH;

/**
 * Standard verify flags (used for mempool validation).
 * @const {VerifyFlags}
 * @default
 */

exports.flags.STANDARD_VERIFY_FLAGS = 0
  | exports.flags.MANDATORY_VERIFY_FLAGS
  | exports.flags.VERIFY_DERSIG
  | exports.flags.VERIFY_STRICTENC
  | exports.flags.VERIFY_MINIMALDATA
  | exports.flags.VERIFY_NULLDUMMY
  | exports.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS
  | exports.flags.VERIFY_CLEANSTACK
  | exports.flags.VERIFY_MINIMALIF
  | exports.flags.VERIFY_NULLFAIL
  | exports.flags.VERIFY_CHECKLOCKTIMEVERIFY
  | exports.flags.VERIFY_CHECKSEQUENCEVERIFY
  | exports.flags.VERIFY_LOW_S
  | exports.flags.VERIFY_WITNESS
  | exports.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
  | exports.flags.VERIFY_WITNESS_PUBKEYTYPE;

/**
 * Standard-not-mandatory flags.
 * @const {VerifyFlags}
 * @default
 */

exports.flags.UNSTANDARD_VERIFY_FLAGS =
  exports.flags.STANDARD_VERIFY_FLAGS & ~exports.flags.MANDATORY_VERIFY_FLAGS;

/**
 * Consensus locktime flags (used for block validation).
 * @const {LockFlags}
 * @default
 */

exports.flags.MANDATORY_LOCKTIME_FLAGS = 0;

/**
 * Standard locktime flags (used for mempool validation).
 * @const {LockFlags}
 * @default
 */

exports.flags.STANDARD_LOCKTIME_FLAGS = 0
  | exports.flags.VERIFY_SEQUENCE
  | exports.flags.MEDIAN_TIME_PAST;

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

/**
 * Bitcoinj-style confidence calculation
 * @enum {Number}
 * @default
 */

exports.confidence = {
  /**
   * Transaction is in the main chain.
   */

  BUILDING: 1,

  /**
   * Transaction is valid and in the mempool.
   */

  PENDING: 2,

  /**
   * Transaction is on a side chain.
   */

  DEAD: 4,

  /**
   * Transaction is double-spent.
   */

  INCONFLICT: 5,

  /**
   * Transaction is not in the mempool or chain.
   */

  UNKNOWN: 0
};

/**
 * The name of our currency.
 * @const {String}
 * @default
 */

exports.CURRENCY_UNIT = 'BTC';
