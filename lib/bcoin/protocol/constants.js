/**
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var utils = require('../utils');

exports.minVersion = 70001;
exports.version = 70012;
// exports.maxMessage = 2 * 1024 * 1024; // main
exports.maxMessage = 4 * 1000 * 1000; // segwit

exports.services = {
  network: (1 << 0),
  getutxo: (1 << 1),
  bloom: (1 << 2),
  witness: (1 << 3)
};

exports.localServices = exports.services.network
  | exports.services.witness;

exports.inv = {
  error: 0,
  tx: 1,
  block: 2,
  filteredblock: 3,
  witnesstx: 1 | (1 << 30),
  witnessblock: 2 | (1 << 30),
  witnessfilteredblock: 3 | (1 << 30)
};

exports.invByVal = utils.revMap(exports.inv);

exports.invWitnessMask = 1 << 30;

exports.filterFlags = {
  none: 0,
  all: 1,
  pubkeyOnly: 2
};

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

exports.opcodesByVal = utils.revMap(exports.opcodes);

exports.coin = new bn(10000000).muln(10);
exports.cent = new bn(1000000);
exports.maxMoney = new bn(21000000).mul(exports.coin);

exports.hashType = {
  all: 1,
  none: 2,
  single: 3,
  anyonecanpay: 0x80
};

exports.hashTypeByVal = utils.revMap(exports.hashType);

exports.block = {
  maxSize: 1000000,
  maxSigops: 1000000 / 50,
  maxOrphanTx: 1000000 / 100,
  medianTimespan: 11,
  bip16time: 1333238400,
  sighashLimit: 1300000000
};

exports.tx = {
  version: 2,
  maxSize: 100000,
  minFee: 10000,
  bareMultisig: true,
  freeThreshold: exports.coin.muln(144).divn(250),
  maxFreeSize: 1000,
  maxSigops: exports.block.maxSigops / 5,
  coinbaseMaturity: 100
};

exports.tx.dustThreshold = 182 * exports.tx.minFee / 1000 * 3;

exports.script = {
  maxSize: 10000,
  maxStack: 1000,
  maxPush: 520,
  maxOps: 201,
  maxPubkeysPerMultisig: 20,
  maxScripthashSigops: 15,
  maxOpReturnBytes: 83,
  maxOpReturn: 80
};

exports.reject = {
  malformed: 0x01,
  invalid: 0x10,
  obsolete: 0x11,
  duplicate: 0x12,
  nonstandard: 0x40,
  dust: 0x41,
  insufficientfee: 0x42,
  checkpoint: 0x43,
  // Internal codes (NOT FOR USE ON NETWORK)
  internal: 0x100,
  highfee: 0x100,
  alreadyknown: 0x101,
  conflict: 0x102
};

exports.rejectByVal = utils.revMap(exports.reject);

exports.hd = {
  hardened: 0x80000000,
  maxIndex: 2 * 0x80000000,
  minEntropy: 128 / 8,
  maxEntropy: 512 / 8,
  parentFingerPrintSize: 4,
  pathRoots: ['m', 'M', 'm\'', 'M\'']
};

exports.locktimeThreshold = 500000000; // Tue Nov 5 00:53:20 1985 UTC

exports.sequenceLocktimeDisableFlag = (1 << 31) >>> 0;
exports.sequenceLocktimeTypeFlag = 1 << 22;
exports.sequenceLocktimeGranularity = 9;
exports.sequenceLocktimeMask = 0x0000ffff;

exports.oneHash = new Buffer(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);

exports.zeroHash = new Buffer(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

exports.nullHash =
  '0000000000000000000000000000000000000000000000000000000000000000';

exports.userVersion = require('../../../package.json').version;
exports.userAgent = '/bcoin:' + exports.userVersion + '/';

exports.banTime = 24 * 60 * 60;
exports.banScore = 100;

// Script and locktime flags
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
  VERIFY_SEQUENCE: (1 << 0),
  MEDIAN_TIME_PAST: (1 << 1)
};

// Block validation
exports.flags.MANDATORY_VERIFY_FLAGS = exports.flags.VERIFY_P2SH;

// Mempool validation
exports.flags.STANDARD_VERIFY_FLAGS =
  exports.flags.MANDATORY_VERIFY_FLAGS
  | exports.flags.VERIFY_DERSIG
  | exports.flags.VERIFY_STRICTENC
  | exports.flags.VERIFY_MINIMALDATA
  | exports.flags.VERIFY_NULLDUMMY
  | exports.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS
  | exports.flags.VERIFY_CLEANSTACK
  | exports.flags.VERIFY_CHECKLOCKTIMEVERIFY
  | exports.flags.VERIFY_LOW_S
  | exports.flags.VERIFY_CHECKSEQUENCEVERIFY;
  // | exports.flags.VERIFY_WITNESS
  // | exports.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM

exports.flags.MANDATORY_LOCKTIME_FLAGS = 0;

exports.flags.STANDARD_LOCKTIME_FLAGS =
  exports.flags.VERIFY_SEQUENCE
  | exports.flags.MEDIAN_TIME_PAST;

exports.versionbits = {
  // What block version to use for new blocks (pre versionbits)
  LAST_OLD_BLOCK_VERSION: 4,
  // What bits to set in version for versionbits blocks
  TOP_BITS: 0x20000000,
  // What bitmask determines whether versionbits is in use
  TOP_MASK: 0xe0000000
};

exports.thresholdStates = {
  DEFINED: 0,
  STARTED: 1,
  LOCKED_IN: 2,
  ACTIVE: 3,
  FAILED: 4
};
