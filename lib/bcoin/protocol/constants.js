/**
 * constants.js - bitcoin constants for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../../bcoin');
var utils = bcoin.utils;

var i;

exports.minVersion = 70001;
exports.version = 70002;

// version - services field
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
  0: 0,
  pushdata1: 0x4c,
  pushdata2: 0x4d,
  pushdata4: 0x4e,
  // negate1: 0x4f,

  nop1: 0x61,
  if_: 0x63,
  notif: 0x64,
  else_: 0x67,
  endif: 0x68,
  verify: 0x69,
  ret: 0x6a,

  toaltstack: 0x6b,
  fromaltstack: 0x6c,
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
  drop2: 0x6d,
  dup2: 0x6e,
  dup3: 0x6f,
  over2: 0x70,
  rot2: 0x71,
  swap2: 0x72,

  cat: 0x74,
  substr: 0x7f,
  left: 0x80,
  right: 0x81,
  size: 0x82,

  invert: 0x83,
  and: 0x84,
  or: 0x85,
  xor: 0x86,
  eq: 0x87,
  eqverify: 0x88,

  add1: 0x8b,
  sub1: 0x8c,
  mul2: 0x8d,
  div2: 0x8e,
  negate: 0x8f,
  abs: 0x90,
  not: 0x91,
  noteq0: 0x92,
  add: 0x93,
  sub: 0x94,
  mul: 0x95,
  div: 0x96,
  mod: 0x97,
  lshift: 0x98,
  rshift: 0x99,
  booland: 0x9a,
  boolor: 0x9b,
  numeq: 0x9c,
  numeqverify: 0x9d,
  numneq: 0x9e,
  lt: 0x9f,
  gt: 0xa0,
  lte: 0xa1,
  gte: 0xa2,
  min: 0xa3,
  max: 0xa4,
  within: 0xa5,

  ripemd160: 0xa6,
  sha1: 0xa7,
  sha256: 0xa8,
  hash160: 0xa9,
  hash256: 0xaa,
  codesep: 0xab,
  checksig: 0xac,
  checksigverify: 0xad,
  checkmultisig: 0xae,
  checkmultisigverify: 0xaf,
  checklocktimeverify: 0xb1
};

exports.opcodes['-1'] = 0x50 + -1;

for (i = 1; i <= 16; i++)
  exports.opcodes[i] = 0x50 + i;

for (i = 0; i <= 7; i++)
  exports.opcodes['nop' + (i + 3)] = 0xb2 + i;

exports.opcodesByVal = new Array(256);
Object.keys(exports.opcodes).forEach(function(name) {
  exports.opcodesByVal[exports.opcodes[name]] = name;
});

// Little-endian hash type
exports.hashType = {
  all: 1,
  none: 2,
  single: 3,
  anyonecanpay: 0x80
};

exports.rhashType = Object.keys(exports.hashType).reduce(function(out, type) {
  out[exports.hashType[type]] = type;
  return out;
}, {});

exports.block = {
  maxSize: 1000000,
  maxSigops: 1000000 / 50,
  maxOrphanTx: 1000000 / 100
};

exports.script = {
  maxSize: 10000,
  maxStack: 1000,
  maxPush: 520,
  maxOps: 201
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

exports.locktimeThreshold = 500000000; // Tue Nov  5 00:53:20 1985 UTC

exports.oneHash = utils.toArray(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);

exports.zeroHash = utils.toArray(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

exports.hd = {
  hardened: 0x80000000,
  maxIndex: 2 * 0x80000000,
  minEntropy: 128 / 8,
  maxEntropy: 512 / 8,
  parentFingerPrintSize: 4,
  pathRoots: ['m', 'M', 'm\'', 'M\'']
};
