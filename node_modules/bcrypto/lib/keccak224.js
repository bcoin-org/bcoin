/*!
 * keccak224.js - Keccak-224 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak224
 */

class Keccak224 extends Keccak {
  constructor() {
    super();
  }

  init() {
    return super.init(224);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak224();
  }

  static hmac() {
    return super.hmac(224, 0x01, null);
  }

  static digest(data) {
    return super.digest(data, 224, 0x01, null);
  }

  static root(left, right) {
    return super.root(left, right, 224, 0x01, null);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 224, 0x01, null);
  }

  static mac(data, key) {
    return super.mac(data, key, 224, 0x01, null);
  }
}

Keccak224.native = Keccak.native;
Keccak224.id = 'KECCAK224';
Keccak224.size = 28;
Keccak224.bits = 224;
Keccak224.blockSize = 144;
Keccak224.zero = Buffer.alloc(28, 0x00);
Keccak224.ctx = new Keccak224();

/*
 * Expose
 */

module.exports = Keccak224;
