/*!
 * keccak256.js - Keccak-256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak256
 */

class Keccak256 extends Keccak {
  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak256();
  }

  static hmac() {
    return super.hmac(256, 0x01, null);
  }

  static digest(data) {
    return super.digest(data, 256, 0x01, null);
  }

  static root(left, right) {
    return super.root(left, right, 256, 0x01, null);
  }

  static multi(x, y, z) {
    return super.multi(x, y, z, 256, 0x01, null);
  }

  static mac(data, key) {
    return super.mac(data, key, 256, 0x01, null);
  }
}

Keccak256.native = Keccak.native;
Keccak256.id = 'KECCAK256';
Keccak256.size = 32;
Keccak256.bits = 256;
Keccak256.blockSize = 136;
Keccak256.zero = Buffer.alloc(32, 0x00);
Keccak256.ctx = new Keccak256();

/*
 * Expose
 */

module.exports = Keccak256;
