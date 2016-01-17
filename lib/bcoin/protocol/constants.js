/**
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;

var i;

exports.minVersion = 70001;
exports.version = 70002;

exports.services = {
  network: 1
};

exports.inv = {
  error: 0,
  tx: 1,
  block: 2,
  filtered: 3
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
  nop3: 0xb2,
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
  maxSigops: 1000000 / 50,
  maxOrphanTx: 1000000 / 100,
  medianTimeSpan: 11,
  bip16time: 1333238400
};

exports.tx = {
  maxSize: 100000,
  fee: 10000,
  dust: 5460,
  bareMultisig: true
};

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

exports.oneHash = utils.toArray(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);

exports.zeroHash = utils.toArray(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

exports.userVersion = require('../../../package.json').version;
exports.userAgent = '/bcoin:' + exports.userVersion + '/';

exports.coin = new bn(10000000).muln(10);
exports.cent = new bn(1000000);
exports.maxMoney = new bn(21000000).mul(exports.coin);
