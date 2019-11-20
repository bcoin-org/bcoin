/*!
 * keccak.js - Keccak implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {Keccak} = require('./binding');
const HMAC = require('../internal/hmac');

Keccak.hash = function hash() {
  return new Keccak();
};

Keccak.hmac = function hmac(bits = 256, pad = 0x01, len) {
  assert((bits >>> 0) === bits);
  const bs = (1600 - bits * 2) / 8;
  return new HMAC(Keccak, bs, [bits], [pad, len]);
};

Keccak.mac = function mac(data, key, bits = 256, pad = 0x01, len) {
  return Keccak.hmac(bits, pad, len).init(key).update(data).final();
};

Keccak.native = 2;
Keccak.id = 'KECCAK256';
Keccak.size = 32;
Keccak.bits = 256;
Keccak.blockSize = 136;
Keccak.zero = Buffer.alloc(32, 0x00);
Keccak.ctx = new Keccak();

module.exports = Keccak;
