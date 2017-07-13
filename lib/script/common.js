/*!
 * common.js - common script functions for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module script/common
 */

const assert = require('assert');
const BN = require('../crypto/bn');
const util = require('../utils/util');
const secp256k1 = require('../crypto/secp256k1');

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
 * Script and locktime flags. See {@link VerifyFlags}.
 * @enum {Number}
 */

exports.flags = {
  VERIFY_NONE: 0,
  VERIFY_P2SH: 1 << 0,
  VERIFY_STRICTENC: 1 << 1,
  VERIFY_DERSIG: 1 << 2,
  VERIFY_LOW_S: 1 << 3,
  VERIFY_NULLDUMMY: 1 << 4,
  VERIFY_SIGPUSHONLY: 1 << 5,
  VERIFY_MINIMALDATA: 1 << 6,
  VERIFY_DISCOURAGE_UPGRADABLE_NOPS: 1 << 7,
  VERIFY_CLEANSTACK: 1 << 8,
  VERIFY_CHECKLOCKTIMEVERIFY: 1 << 9,
  VERIFY_CHECKSEQUENCEVERIFY: 1 << 10,
  VERIFY_WITNESS: 1 << 11,
  VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: 1 << 12,
  VERIFY_MINIMALIF: 1 << 13,
  VERIFY_NULLFAIL: 1 << 14,
  VERIFY_WITNESS_PUBKEYTYPE: 1 << 15,
  VERIFY_MAST: 1 << 16
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
 * Standard flags without mandatory bits.
 * @const {VerifyFlags}
 * @default
 */

exports.flags.ONLY_STANDARD_VERIFY_FLAGS =
  exports.flags.STANDARD_VERIFY_FLAGS & ~exports.flags.MANDATORY_VERIFY_FLAGS;

/**
 * Sighash Types.
 * @enum {SighashType}
 * @default
 */

exports.hashType = {
  /*
   * Sign all outputs.
   */

  ALL: 1,

  /*
   * Do not sign outputs (zero sequences).
   */

  NONE: 2,

  /*
   * Sign output at the same index (zero sequences).
   */

  SINGLE: 3,

  /*
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
 * Output script types.
 * @enum {Number}
 */

exports.types = {
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

exports.typesByVal = util.revMap(exports.types);

/**
 * False stack return value.
 * @const {Buffer}
 */

exports.STACK_FALSE = Buffer.from([]);

/**
 * True stack return value.
 * @const {Buffer}
 */

exports.STACK_TRUE = Buffer.from([0x01]);

/**
 * -1 stack return value.
 * @const {Buffer}
 */

exports.STACK_NEGATE = Buffer.from([0x81]);

/**
 * Test a signature to see whether it contains a valid sighash type.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

exports.isHashType = function isHashType(sig) {
  let type;

  assert(Buffer.isBuffer(sig));

  if (sig.length === 0)
    return false;

  type = sig[sig.length - 1] & ~exports.hashType.ANYONECANPAY;

  if (!(type >= exports.hashType.ALL && type <= exports.hashType.SINGLE))
    return false;

  return true;
};

/**
 * Test a signature to see whether it contains a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

exports.isLowDER = function isLowDER(sig) {
  if (!exports.isSignatureEncoding(sig))
    return false;

  return secp256k1.isLowS(sig.slice(0, -1));
};

/**
 * Get a small integer from an opcode (OP_0-OP_16).
 * @param {Number} index
 * @returns {Number}
 */

exports.getSmall = function getSmall(op) {
  assert(typeof op === 'number');

  if (op === exports.opcodes.OP_0)
    return 0;

  if (op >= exports.opcodes.OP_1 && op <= exports.opcodes.OP_16)
    return op - 0x50;

  return -1;
};

/**
 * Test whether the data element is a ripemd160 hash.
 * @param {Buffer?} hash
 * @returns {Boolean}
 */

exports.isHash = function isHash(hash) {
  return Buffer.isBuffer(hash) && hash.length === 20;
};

/**
 * Test whether the data element is a public key. Note that
 * this does not verify the format of the key, only the length.
 * @param {Buffer?} key
 * @returns {Boolean}
 */

exports.isKey = function isKey(key) {
  return Buffer.isBuffer(key) && key.length >= 33 && key.length <= 65;
};

/**
 * Test whether the data element is a signature. Note that
 * this does not verify the format of the signature, only the length.
 * @param {Buffer?} sig
 * @returns {Boolean}
 */

exports.isSignature = function isSignature(sig) {
  return Buffer.isBuffer(sig) && sig.length >= 9 && sig.length <= 73;
};

/**
 * Test whether the data element is a valid key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

exports.isKeyEncoding = function isKeyEncoding(key) {
  assert(Buffer.isBuffer(key));

  if (key.length < 33)
    return false;

  if (key[0] === 0x04) {
    if (key.length !== 65)
      return false;
  } else if (key[0] === 0x02 || key[0] === 0x03) {
    if (key.length !== 33)
      return false;
  } else {
    return false;
  }

  return true;
};

/**
 * Test whether the data element is a compressed key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

exports.isCompressedEncoding = function isCompressedEncoding(key) {
  assert(Buffer.isBuffer(key));

  if (key.length !== 33)
    return false;

  if (key[0] !== 0x02 && key[0] !== 0x03)
    return false;

  return true;
};

/**
 * Test a signature to see if it abides by BIP66.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 * @param {Buffer} sig
 * @returns {Boolean}
 */

exports.isSignatureEncoding = function isSignatureEncoding(sig) {
  let lenR, lenS;

  assert(Buffer.isBuffer(sig));

  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
  // * total-length: 1-byte length descriptor of everything that follows,
  //   excluding the sighash byte.
  // * R-length: 1-byte length descriptor of the R value that follows.
  // * R: arbitrary-length big-endian encoded R value. It must use the shortest
  //   possible encoding for a positive integers (which means no null bytes at
  //   the start, except a single one when the next byte has its highest bit set).
  // * S-length: 1-byte length descriptor of the S value that follows.
  // * S: arbitrary-length big-endian encoded S value. The same rules apply.
  // * sighash: 1-byte value indicating what data is hashed (not part of the DER
  //   signature)

  // Minimum and maximum size constraints.
  if (sig.length < 9)
    return false;

  if (sig.length > 73)
    return false;

  // A signature is of type 0x30 (compound).
  if (sig[0] !== 0x30)
    return false;

  // Make sure the length covers the entire signature.
  if (sig[1] !== sig.length - 3)
    return false;

  // Extract the length of the R element.
  lenR = sig[3];

  // Make sure the length of the S element is still inside the signature.
  if (5 + lenR >= sig.length)
    return false;

  // Extract the length of the S element.
  lenS = sig[5 + lenR];

  // Verify that the length of the signature matches the sum of the length
  // of the elements.
  if (lenR + lenS + 7 !== sig.length)
    return false;

  // Check whether the R element is an integer.
  if (sig[2] !== 0x02)
    return false;

  // Zero-length integers are not allowed for R.
  if (lenR === 0)
    return false;

  // Negative numbers are not allowed for R.
  if (sig[4] & 0x80)
    return false;

  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (lenR > 1 && (sig[4] === 0x00) && !(sig[5] & 0x80))
    return false;

  // Check whether the S element is an integer.
  if (sig[lenR + 4] !== 0x02)
    return false;

  // Zero-length integers are not allowed for S.
  if (lenS === 0)
    return false;

  // Negative numbers are not allowed for S.
  if (sig[lenR + 6] & 0x80)
    return false;

  // Null bytes at the start of S are not allowed, unless S would otherwise be
  // interpreted as a negative number.
  if (lenS > 1 && (sig[lenR + 6] === 0x00) && !(sig[lenR + 7] & 0x80))
    return false;

  return true;
};

/**
 * Format script code into a human readable-string.
 * @param {Array} code
 * @returns {String} Human-readable string.
 */

exports.formatStack = function formatStack(items) {
  let out = [];

  for (let item of items)
    out.push(item.toString('hex'));

  return out.join(' ');
};

/**
 * Format script code into a human readable-string.
 * @param {Array} code
 * @returns {String} Human-readable string.
 */

exports.formatCode = function formatCode(code) {
  let out = [];

  for (let op of code) {
    let data = op.data;
    let value = op.value;

    if (data) {
      let size = data.length.toString(16);

      while (size.length % 2 !== 0)
        size = '0' + size;

      if (!exports.opcodesByVal[value]) {
        value = value.toString(16);
        if (value.length < 2)
          value = '0' + value;
        value = `0x${value} 0x${data.toString('hex')}`;
        out.push(value);
        continue;
      }

      value = exports.opcodesByVal[value];
      value = `${value} 0x${size} 0x${data.toString('hex')}`;
      out.push(value);
      continue;
    }

    assert(typeof value === 'number');

    if (exports.opcodesByVal[value]) {
      value = exports.opcodesByVal[value];
      out.push(value);
      continue;
    }

    if (value === -1) {
      out.push('OP_INVALIDOPCODE');
      break;
    }

    value = value.toString(16);

    if (value.length < 2)
      value = '0' + value;

    value = `0x${value}`;
    out.push(value);
  }

  return out.join(' ');
};

/**
 * Format script code into bitcoind asm format.
 * @param {Array} code
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable string.
 */

exports.formatItem = function formatItem(data, decode) {
  if (data.length <= 4) {
    data = exports.num(data, exports.flags.VERIFY_NONE);
    return data.toString(10);
  }

  if (decode) {
    let symbol = '';
    if (exports.isSignatureEncoding(data)) {
      let type = data[data.length - 1];

      symbol = exports.hashTypeByVal[type & 0x1f] || '';

      if (symbol) {
        if (type & exports.hashType.ANYONECANPAY)
          symbol += '|ANYONECANPAY';
        symbol = `[${symbol}]`;
      }

      data = data.slice(0, -1);
    }
    return data.toString('hex') + symbol;
  }

  return data.toString('hex');
};

/**
 * Format script code into bitcoind asm format.
 * @param {Array} code
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable string.
 */

exports.formatASM = function formatASM(code, decode) {
  let out = [];

  if (code.length > 0 && code[0].value === exports.opcodes.OP_RETURN)
    decode = false;

  for (let op of code) {
    let data = op.data;
    let value = op.value;

    if (value === -1) {
      out.push('[error]');
      break;
    }

    if (data) {
      data = exports.formatItem(data, decode);
      out.push(data);
      continue;
    }

    value = exports.opcodesByVal[value] || 'OP_UNKNOWN';

    out.push(value);
  }

  return out.join(' ');
};

/**
 * Format script code into bitcoind asm format.
 * @param {Array} code
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable string.
 */

exports.formatStackASM = function formatStackASM(items, decode) {
  let out = [];

  for (let item of items) {
    let data = exports.formatItem(item, decode);
    out.push(data);
  }

  return out.join(' ');
};

/**
 * Create a CScriptNum.
 * @param {Buffer} value
 * @param {Boolean?} minimal
 * @param {Number?} size - Max size in bytes.
 * @returns {BN}
 * @throws {ScriptError}
 */

exports.num = function num(value, minimal, size) {
  let result;

  assert(Buffer.isBuffer(value));

  if (size == null)
    size = 4;

  if (value.length > size)
    throw new exports.ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  if (minimal && value.length > 0) {
    // If the low bits on the last byte are unset,
    // fail if the value's second to last byte does
    // not have the high bit set. A number can't
    // justify having the last byte's low bits unset
    // unless they ran out of space for the sign bit
    // in the second to last bit. We also fail on [0]
    // to avoid negative zero (also avoids positive
    // zero).
    if (!(value[value.length - 1] & 0x7f)) {
      if (value.length === 1 || !(value[value.length - 2] & 0x80)) {
        throw new exports.ScriptError(
          'UNKNOWN_ERROR',
          'Non-minimally encoded Script number.');
      }
    }
  }

  if (value.length === 0)
    return new BN(0);

  result = new BN(value, 'le');

  // If the input vector's most significant byte is
  // 0x80, remove it from the result's msb and return
  // a negative.
  // Equivalent to:
  // -(result & ~(0x80 << (8 * (value.length - 1))))
  if (value[value.length - 1] & 0x80)
    result.setn((value.length * 8) - 1, 0).ineg();

  return result;
};

/**
 * Create a script array. Will convert Numbers and big
 * numbers to a little-endian buffer while taking into
 * account negative zero, minimaldata, etc.
 * @example
 * assert.deepEqual(Script.array(0), Buffer.alloc(0));
 * assert.deepEqual(Script.array(0xffee), Buffer.from('eeff00', 'hex'));
 * assert.deepEqual(Script.array(new BN(0xffee)), Buffer.from('eeff00', 'hex'));
 * assert.deepEqual(Script.array(new BN(0x1e).ineg()), Buffer.from('9e', 'hex'));
 * @param {Number|BN} value
 * @returns {Buffer}
 */

exports.array = function array(value) {
  let neg, result;

  if (util.isNumber(value))
    value = new BN(value);

  assert(BN.isBN(value));

  if (value.cmpn(0) === 0)
    return exports.STACK_FALSE;

  // If the most significant byte is >= 0x80
  // and the value is positive, push a new
  // zero-byte to make the significant
  // byte < 0x80 again.

  // If the most significant byte is >= 0x80
  // and the value is negative, push a new
  // 0x80 byte that will be popped off when
  // converting to an integral.

  // If the most significant byte is < 0x80
  // and the value is negative, add 0x80 to
  // it, since it will be subtracted and
  // interpreted as a negative when
  // converting to an integral.

  neg = value.cmpn(0) < 0;
  result = value.toArray('le');

  if (result[result.length - 1] & 0x80)
    result.push(neg ? 0x80 : 0);
  else if (neg)
    result[result.length - 1] |= 0x80;

  return Buffer.from(result);
};

/**
 * An error thrown from the scripting system,
 * potentially pertaining to Script execution.
 * @alias module:script.ScriptError
 * @constructor
 * @extends Error
 * @param {String} code - Error code.
 * @param {Opcode} op - Opcode.
 * @param {Number?} ip - Instruction pointer.
 * @property {String} message - Error message.
 * @property {String} code - Original code passed in.
 * @property {Number} op - Opcode.
 * @property {Number} ip - Instruction pointer.
 */

exports.ScriptError = function ScriptError(code, op, ip) {
  if (!(this instanceof ScriptError))
    return new ScriptError(code, op, ip);

  Error.call(this);

  this.type = 'ScriptError';
  this.code = code;
  this.message = code;
  this.op = -1;
  this.ip = -1;

  if (typeof op === 'string') {
    this.message = op;
  } else if (op) {
    this.message = `${code} (op=${op.toSymbol()}, ip=${ip})`;
    this.op = op.value;
    this.ip = ip;
  }

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, ScriptError);
};

util.inherits(exports.ScriptError, Error);
