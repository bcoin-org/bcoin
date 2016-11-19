/*!
 * mine.js - mining function for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var crypto = require('../crypto/crypto');
var assert = require('assert');

/**
 * Hash until the nonce overflows.
 * @param {Buffer} data
 * @param {Buffer} target - Big endian.
 * @param {Number} min
 * @param {Number} max
 * @returns {Number} Nonce or -1.
 */

function mine(data, target, min, max) {
  var nonce = min;

  data.writeUInt32LE(nonce, 76, true);

  // The heart and soul of the miner: match the target.
  while (nonce <= max) {
    // Hash and test against the next target.
    if (rcmp(crypto.hash256(data), target) <= 0)
      return nonce;

    // Increment the nonce to get a different hash
    nonce++;

    // Update the raw buffer (faster than
    // constantly serializing the headers).
    data.writeUInt32LE(nonce, 76, true);
  }

  return -1;
}

/**
 * "Reverse" comparison so we don't have
 * to waste time reversing the block hash.
 * @memberof Miner
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number}
 */

function rcmp(a, b) {
  var i;

  assert(a.length === b.length);

  for (i = a.length - 1; i >= 0; i--) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  return 0;
}

/*
 * Expose
 */

module.exports = mine;
