/*!
 * common.js - mining utils
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * @exports mining/common
 */

var common = exports;

/*
 * Constants
 */

var DIFF_TARGET = 0x00000000ffff0000000000000000000000000000000000000000000000000000;
var B192 = 0x1000000000000000000000000000000000000000000000000;
var B128 = 0x100000000000000000000000000000000;
var B64 = 0x10000000000000000;
var B0 = 0x1;

/**
 * Swap 32 bit endianness of uint256.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.swap32 = function swap32(data) {
  var i, field;

  for (i = 0; i < data.length; i += 4) {
    field = data.readUInt32LE(i, true);
    data.writeUInt32BE(field, i, true);
  }

  return data;
};

/**
 * Swap 32 bit endianness of uint256 (hex).
 * @param {String} data
 * @returns {String}
 */

exports.hswap32 = function hswap32(hex) {
  var data = new Buffer(hex, 'hex');
  exports.swap32(data)
  return data.toString('hex');
};

/**
 * Compare two uint256le's.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number}
 */

exports.rcmp = function rcmp(a, b) {
  var i;

  assert(a.length === b.length);

  for (i = a.length - 1; i >= 0; i--) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  return 0;
};

/**
 * Convert a uint256le to a double.
 * @param {Buffer} target
 * @returns {Number}
 */

exports.double256 = function double256(target) {
  var n = 0;
  var hi, lo;

  assert(target.length === 32);

  hi = target.readUInt32LE(28, true);
  lo = target.readUInt32LE(24, true);
  n += (hi * 0x100000000 + lo) * B192;

  hi = target.readUInt32LE(20, true);
  lo = target.readUInt32LE(16, true);
  n += (hi * 0x100000000 + lo) * B128;

  hi = target.readUInt32LE(12, true);
  lo = target.readUInt32LE(8, true);
  n += (hi * 0x100000000 + lo) * B64;

  hi = target.readUInt32LE(4, true);
  lo = target.readUInt32LE(0, true);
  n += (hi * 0x100000000 + lo) * B0;

  return n;
};

/**
 * Calculate mining difficulty
 * from little-endian target.
 * @param {Buffer} target
 * @returns {Number}
 */

exports.getDifficulty = function getDifficulty(target) {
  var d = DIFF_TARGET;
  var n = exports.double256(target);
  if (n === 0)
    return d;
  if (n > d)
    return d;
  return Math.floor(d / n);
};
