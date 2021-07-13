/*!
 * keccak384.js - Keccak-384 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak384
 */

class Keccak384 extends Keccak {
  constructor() {
    super();
  }

  init() {
    return super.init(384);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak384();
  }

  static hmac() {
    return super.hmac(384, 0x01, null);
  }

  static digest(data) {
    return super.digest(data, 384, 0x01, null);
  }

  static root(left, right) {
    return super.root(left, right, 384, 0x01, null);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 384, 0x01, null);
  }

  static mac(data, key) {
    return super.mac(data, key, 384, 0x01, null);
  }
}

Keccak384.native = Keccak.native;
Keccak384.id = 'KECCAK384';
Keccak384.size = 48;
Keccak384.bits = 384;
Keccak384.blockSize = 104;
Keccak384.zero = Buffer.alloc(48, 0x00);
Keccak384.ctx = new Keccak384();

/*
 * Expose
 */

module.exports = Keccak384;
