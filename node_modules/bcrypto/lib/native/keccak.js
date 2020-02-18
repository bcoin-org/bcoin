/*!
 * keccak.js - Keccak implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const {Keccak} = require('./binding');
const HMAC = require('../internal/hmac');

/*
 * Keccak
 */

Keccak.hash = function hash() {
  return new Keccak();
};

Keccak.hmac = function hmac(bits, pad, len) {
  if (bits == null)
    bits = 256;

  assert((bits >>> 0) === bits);

  const rate = 1600 - bits * 2;

  return new HMAC(Keccak, rate / 8, [bits], [pad, len]);
};

Keccak.mac = function mac(data, key, bits, pad, len) {
  return Keccak.hmac(bits, pad, len).init(key).update(data).final();
};

/*
 * Static
 */

Keccak.native = 2;
Keccak.id = 'KECCAK256';
Keccak.size = 32;
Keccak.bits = 256;
Keccak.blockSize = 136;
Keccak.zero = Buffer.alloc(32, 0x00);
Keccak.ctx = new Keccak();

/*
 * Expose
 */

module.exports = Keccak;
