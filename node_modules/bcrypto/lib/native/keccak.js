/*!
 * keccak.js - Keccak implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const HMAC = require('../internal/hmac');

/**
 * Keccak
 */

class Keccak {
  constructor() {
    this._handle = binding.keccak_create();
  }

  init(bits) {
    if (bits == null)
      bits = 256;

    assert(this instanceof Keccak);
    assert((bits >>> 0) === bits);

    binding.keccak_init(this._handle, bits);

    return this;
  }

  update(data) {
    assert(this instanceof Keccak);
    assert(Buffer.isBuffer(data));

    binding.keccak_update(this._handle, data);

    return this;
  }

  final(pad, len) {
    if (pad == null)
      pad = 0x01;

    if (len == null)
      len = 0;

    assert(this instanceof Keccak);
    assert((pad >>> 0) === pad);
    assert((len >>> 0) === len);

    return binding.keccak_final(this._handle, pad, len);
  }

  static hash() {
    return new Keccak();
  }

  static hmac(bits, pad, len) {
    if (bits == null)
      bits = 256;

    if (pad == null)
      pad = 0x01;

    if (len == null)
      len = 0;

    assert((bits >>> 0) === bits);
    assert((pad >>> 0) === pad);
    assert((len >>> 0) === len);

    const rate = 1600 - bits * 2;
    const bs = rate >> 3;

    return new HMAC(Keccak, bs, [bits], [pad, len]);
  }

  static digest(data, bits, pad, len) {
    if (bits == null)
      bits = 256;

    if (pad == null)
      pad = 0x01;

    if (len == null)
      len = 0;

    assert(Buffer.isBuffer(data));
    assert((bits >>> 0) === bits);
    assert((pad >>> 0) === pad);
    assert((len >>> 0) === len);

    return binding.keccak_digest(data, bits, pad, len);
  }

  static root(left, right, bits, pad, len) {
    if (bits == null)
      bits = 256;

    if (pad == null)
      pad = 0x01;

    if (len == null)
      len = 0;

    assert(Buffer.isBuffer(left));
    assert(Buffer.isBuffer(right));
    assert((bits >>> 0) === bits);
    assert((pad >>> 0) === pad);
    assert((len >>> 0) === len);

    return binding.keccak_root(left, right, bits, pad, len);
  }

  static multi(x, y, z, bits, pad, len) {
    if (z == null)
      z = binding.NULL;

    if (bits == null)
      bits = 256;

    if (pad == null)
      pad = 0x01;

    if (len == null)
      len = 0;

    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));
    assert(Buffer.isBuffer(z));
    assert((bits >>> 0) === bits);
    assert((pad >>> 0) === pad);
    assert((len >>> 0) === len);

    return binding.keccak_multi(x, y, z, bits, pad, len);
  }

  static mac(data, key, bits, pad, len) {
    return Keccak.hmac(bits, pad, len).init(key).update(data).final();
  }
}

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
