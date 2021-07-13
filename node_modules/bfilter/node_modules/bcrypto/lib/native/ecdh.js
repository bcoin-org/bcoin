/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://cr.yp.to/ecdh.html
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ECDH
 */

class ECDH extends binding.ECDH {
  constructor(name) {
    super(binding.curves.ecdh[name]);

    this.id = name;
    this.type = 'ecdh';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  privateKeyExport(key, sign) {
    const pub = this.publicKeyCreate(key);
    const [x, y] = super.publicKeyExport(pub, sign);

    return {
      d: Buffer.from(key),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    return super.privateKeyImport(json.d);
  }

  publicKeyExport(key, sign) {
    const [x, y] = super.publicKeyExport(key, sign);
    return { x, y };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');
    return super.publicKeyImport(json.x);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    return super.publicKeyToUniform(key, hint);
  }

  publicKeyToHash(key) {
    return super.publicKeyToHash(key, binding.entropy());
  }
}

/*
 * Expose
 */

module.exports = ECDH;
