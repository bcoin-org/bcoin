/*!
 * keccak512.js - Keccak-512 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak512
 */

class Keccak512 extends Keccak {
  constructor() {
    super();
  }

  init() {
    return super.init(512);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak512();
  }

  static hmac() {
    return super.hmac(512, 0x01, null);
  }

  static digest(data) {
    return super.digest(data, 512, 0x01, null);
  }

  static root(left, right) {
    return super.root(left, right, 512, 0x01, null);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 512, 0x01, null);
  }

  static mac(data, key) {
    return super.mac(data, key, 512, 0x01, null);
  }
}

Keccak512.native = Keccak.native;
Keccak512.id = 'KECCAK512';
Keccak512.size = 32;
Keccak512.bits = 512;
Keccak512.blockSize = 72;
Keccak512.zero = Buffer.alloc(32, 0x00);
Keccak512.ctx = new Keccak512();

/*
 * Expose
 */

module.exports = Keccak512;
