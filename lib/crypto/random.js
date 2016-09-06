/*!
 * random.js - pseudorandom byte generation for bcoin.
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on brorand:
 * https://github.com/indutny/brorand
 * Copyright (c) 2014, Fedor Indutny (MIT License).
 */

var random, crypto, global;

try {
  crypto = require('crypto');
} catch (e) {
  ;
}

if (crypto) {
  random = function random(n) {
    return crypto.randomBytes(n);
  };
} else {
  if (typeof window !== 'undefined')
    global = window;
  else if (typeof self !== 'undefined')
    global = self;

  if (!global)
    throw new Error('Unknown global.');

  crypto = global.crypto || global.msCrypto;

  if (crypto && crypto.getRandomValues) {
    random = function random(n) {
      var data = new Uint8Array(n);
      crypto.getRandomValues(data);
      return new Buffer(data.buffer);
    };
  } else {
    // Out of luck here. Use bad randomness for now.
    // Possibly fall back to randy in the future:
    // https://github.com/deestan/randy
    random = function random(n) {
      var data = new Buffer(n);
      var i;

      for (i = 0; i < data.length; i++)
        data[i] = ((Math.random() * 0x100000000) >>> 0) % 256;

      return data;
    };
  }
}

function randomInt(min, max) {
  var num = random(4).readUInt32LE(0, true);
  return Math.floor((num / 0x100000000) * (max - min) + min);
}

/*
 * Expose
 */

exports = random;
exports.randomBytes = random;
exports.randomInt = randomInt;

module.exports = random;
