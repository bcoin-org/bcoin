/*!
 * encoding.js - script-related encoding for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var BN = require('bn.js');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var assert = require('assert');
var opcodes = constants.opcodes;
var STACK_FALSE = new Buffer(0);
var ScriptError = require('../btc/errors').ScriptError;

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
 * Test whether the data element is a null dummy (a zero-length array).
 * @param {Buffer?} data
 * @returns {Boolean}
 */

exports.isDummy = function isDummy(data) {
  return Buffer.isBuffer(data) && data.length === 0;
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
 * Test a signature to see if it abides by BIP66.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 * @param {Buffer} sig
 * @returns {Boolean}
 */

exports.isSignatureEncoding = function isSignatureEncoding(sig) {
  var lenR, lenS;

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
  var out = [];
  var i;

  for (i = 0; i < items.length; i++)
    out.push(items[i].toString('hex'));

  return out.join(' ');
};

/**
 * Format script code into a human readable-string.
 * @param {Array} code
 * @returns {String} Human-readable string.
 */

exports.formatCode = function formatCode(code) {
  var out = [];
  var i, op, data, value, size;

  for (i = 0; i < code.length; i++) {
    op = code[i];
    data = op.data;
    value = op.value;

    if (data) {
      size = data.length.toString(16);

      while (size.length % 2 !== 0)
        size = '0' + size;

      if (!constants.opcodesByVal[value]) {
        value = value.toString(16);
        if (value.length < 2)
          value = '0' + value;
        value = '0x' + value + ' 0x' + data.toString('hex');
        out.push(value);
        continue;
      }

      value = constants.opcodesByVal[value];
      value = value + ' 0x' + size + ' 0x' + data.toString('hex');
      out.push(value);
      continue;
    }

    assert(typeof value === 'number');

    if (constants.opcodesByVal[value]) {
      value = constants.opcodesByVal[value];
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

    value = '0x' + value;
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
  var symbol, type;

  if (data.length <= 4) {
    data = exports.num(data, constants.flags.VERIFY_NONE);
    return data.toString(10);
  }

  if (decode) {
    symbol = '';
    if (exports.isSignatureEncoding(data)) {
      type = data[data.length - 1];
      symbol = constants.hashTypeByVal[type & 0x1f] || '';
      if (symbol) {
        if (type & constants.hashType.ANYONECANPAY)
          symbol += '|ANYONECANPAY';
        symbol = '[' + symbol + ']';
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
  var out = [];
  var i, op, data, value;

  if (code.length > 0 && code[0].value === opcodes.OP_RETURN)
    decode = false;

  for (i = 0; i < code.length; i++) {
    op = code[i];
    data = op.data;
    value = op.value;

    if (value === -1) {
      out.push('[error]');
      break;
    }

    if (data) {
      data = exports.formatItem(data, decode);
      out.push(data);
      continue;
    }

    value = constants.opcodesByVal[value] || 'OP_UNKNOWN';

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
  var out = [];
  var i, item, data;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    data = exports.formatItem(item, decode);
    out.push(data);
  }

  return out.join(' ');
};

/**
 * Create a CScriptNum.
 * @param {Buffer} value
 * @param {Number?} flags - Script standard flags.
 * @param {Number?} size - Max size in bytes.
 * @returns {BN}
 * @throws {ScriptError}
 */

exports.num = function num(value, flags, size) {
  var result;

  assert(Buffer.isBuffer(value));

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (size == null)
    size = 4;

  if (value.length > size)
    throw new ScriptError('UNKNOWN_ERROR', 'Script number overflow.');

  if ((flags & constants.flags.VERIFY_MINIMALDATA) && value.length > 0) {
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
        throw new ScriptError(
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
 * assert.deepEqual(Script.array(0), new Buffer(0));
 * assert.deepEqual(Script.array(0xffee), new Buffer('eeff00', 'hex'));
 * assert.deepEqual(Script.array(new BN(0xffee)), new Buffer('eeff00', 'hex'));
 * assert.deepEqual(Script.array(new BN(0x1e).ineg()), new Buffer('9e', 'hex'));
 * @param {Number|BN} value
 * @returns {Buffer}
 */

exports.array = function(value) {
  var neg, result;

  if (util.isNumber(value))
    value = new BN(value);

  assert(BN.isBN(value));

  if (value.cmpn(0) === 0)
    return STACK_FALSE;

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

  return new Buffer(result);
};
