/**
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');

exports.minVersion = 70001;
exports.version = 70002;
// exports.maxMessage = 2 * 1024 * 1024; // main
exports.maxMessage = 4 * 1000 * 1000; // segwit
exports.bcoinServices = 0;

exports.services = {
  network: (1 << 0),
  getutxo: (1 << 1),
  bloom: (1 << 2),
  witness: (1 << 3)
};

exports.inv = {
  error: 0,
  tx: 1,
  block: 2,
  filtered: 3,
  witnesstx: 1 | (1 << 30),
  witnessblock: 2 | (1 << 30),
  witnessfiltered: 3 | (1 << 30)
};

exports.invByVal = {
  0: 'error',
  1: 'tx',
  2: 'block',
  3: 'filtered'
};

exports.filterFlags = {
  none: 0,
  all: 1,
  pubkeyOnly: 2
};

exports.opcodes = {
  // 'false': 0x00,
  '0': 0x00,

  pushdata1: 0x4c,
  pushdata2: 0x4d,
  pushdata4: 0x4e,

  '1negate': 0x4f,

  reserved: 0x50,

  // 'true': 0x51,
  '1': 0x51,
  '2': 0x52,
  '3': 0x53,
  '4': 0x54,
  '5': 0x55,
  '6': 0x56,
  '7': 0x57,
  '8': 0x58,
  '9': 0x59,
  '10': 0x5a,
  '11': 0x5b,
  '12': 0x5c,
  '13': 0x5d,
  '14': 0x5e,
  '15': 0x5f,
  '16': 0x60,

  nop: 0x61,
  ver: 0x62,
  'if': 0x63,
  notif: 0x64,
  verif: 0x65,
  vernotif: 0x66,
  'else': 0x67,
  endif: 0x68,
  verify: 0x69,
  'return': 0x6a,

  toaltstack: 0x6b,
  fromaltstack: 0x6c,
  '2drop': 0x6d,
  '2dup': 0x6e,
  '3dup': 0x6f,
  '2over': 0x70,
  '2rot': 0x71,
  '2swap': 0x72,
  ifdup: 0x73,
  depth: 0x74,
  drop: 0x75,
  dup: 0x76,
  nip: 0x77,
  over: 0x78,
  pick: 0x79,
  roll: 0x7a,
  rot: 0x7b,
  swap: 0x7c,
  tuck: 0x7d,

  cat: 0x7e,
  substr: 0x7f,
  left: 0x80,
  right: 0x81,
  size: 0x82,

  invert: 0x83,
  and: 0x84,
  or: 0x85,
  xor: 0x86,
  equal: 0x87,
  equalverify: 0x88,

  reserved1: 0x89,
  reserved2: 0x8a,

  '1add': 0x8b,
  '1sub': 0x8c,
  '2mul': 0x8d,
  '2div': 0x8e,
  negate: 0x8f,
  abs: 0x90,
  not: 0x91,
  '0notequal': 0x92,
  add: 0x93,
  sub: 0x94,
  mul: 0x95,
  div: 0x96,
  mod: 0x97,
  lshift: 0x98,
  rshift: 0x99,
  booland: 0x9a,
  boolor: 0x9b,
  numequal: 0x9c,
  numequalverify: 0x9d,
  numnotequal: 0x9e,
  lessthan: 0x9f,
  greaterthan: 0xa0,
  lessthanorequal: 0xa1,
  greaterthanorequal: 0xa2,
  min: 0xa3,
  max: 0xa4,
  within: 0xa5,

  ripemd160: 0xa6,
  sha1: 0xa7,
  sha256: 0xa8,
  hash160: 0xa9,
  hash256: 0xaa,
  codeseparator: 0xab,
  checksig: 0xac,
  checksigverify: 0xad,
  checkmultisig: 0xae,
  checkmultisigverify: 0xaf,

  // 'eval': 0xb0,
  nop1: 0xb0,
  // nop2: 0xb1,
  checklocktimeverify: 0xb1,
  // nop3: 0xb2,
  checksequenceverify: 0xb2,
  nop4: 0xb3,
  nop5: 0xb4,
  nop6: 0xb5,
  nop7: 0xb6,
  nop8: 0xb7,
  nop9: 0xb8,
  nop10: 0xb9,

  pubkeyhash: 0xfd,
  pubkey: 0xfe,
  invalidopcode: 0xff
};

exports.opcodesByVal = new Array(256);
Object.keys(exports.opcodes).forEach(function(name) {
  var val = exports.opcodes[name];
  // if (val === 0x00 || (val >= 0x51 && val <= 0x60))
  //   name = +name;
  exports.opcodesByVal[val] = name;
});

exports.coin = new bn(10000000).muln(10);
exports.cent = new bn(1000000);
exports.maxMoney = new bn(21000000).mul(exports.coin);

exports.hashType = {
  all: 1,
  none: 2,
  single: 3,
  anyonecanpay: 0x80
};

exports.hashTypeByVal = Object.keys(exports.hashType).reduce(function(out, type) {
  out[exports.hashType[type]] = type;
  return out;
}, {});

exports.block = {
  maxSize: 1000000,
  maxCost: 4000000,
  maxSigops: 1000000 / 50,
  maxSigopsCost: 4000000 / 50,
  maxOrphanTx: 1000000 / 100,
  medianTimespan: 11,
  bip16time: 1333238400
};

exports.tx = {
  version: 1,
  maxSize: 100000,
  maxCost: 400000,
  minFee: 10000,
  bareMultisig: true,
  freeThreshold: exports.coin.muln(144).divn(250),
  maxFreeSize: 1000
};

exports.tx.dustThreshold = new bn(182)
  .muln(exports.tx.minFee)
  .divn(1000)
  .muln(3)
  .toNumber();

exports.script = {
  maxSize: 10000,
  maxStack: 1000,
  maxPush: 520,
  maxOps: 201,
  maxPubkeysPerMultisig: 20,
  maxBlockSigops: exports.block.maxSize / 50,
  maxScripthashSigops: 15,
  maxTxSigops: exports.block.maxSize / 50 / 5,
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
  checkpoint: 0x43
};

exports.rejectByVal = Object.keys(exports.reject).reduce(function(out, name) {
  out[exports.reject[name]] = name;
  return out;
}, {});

exports.hd = {
  hardened: 0x80000000,
  maxIndex: 2 * 0x80000000,
  minEntropy: 128 / 8,
  maxEntropy: 512 / 8,
  parentFingerPrintSize: 4,
  pathRoots: ['m', 'M', 'm\'', 'M\'']
};

exports.locktimeThreshold = 500000000; // Tue Nov 5 00:53:20 1985 UTC

exports.sequenceLocktimeDisableFlag = 0x80000000; // (1 << 31)
exports.sequenceLocktimeTypeFlag = 1 << 22;
exports.sequenceLocktimeMask = 0x0000ffff;

exports.oneHash = new Buffer(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);

exports.zeroHash = new Buffer(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

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
  VERIFY_WITNESS: (1 << 10),
  VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: (1 << 11),
  // NOTE: Should be (1 << 10) - but that conflicts with segwit
  VERIFY_CHECKSEQUENCEVERIFY: (1 << 12)
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
  | exports.flags.VERIFY_LOW_S;
  // | exports.flags.VERIFY_WITNESS
  // | exports.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
  // | exports.flags.VERIFY_CHECKSEQUENCEVERIFY;

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
