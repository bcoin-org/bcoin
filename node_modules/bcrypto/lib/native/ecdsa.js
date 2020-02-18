/*!
 * ecdsa.js - ecdsa wrapper for libtorsion
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ECDSA
 */

class ECDSA extends binding.ECDSA {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'ecdsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;

    this._randomize(binding.entropy());
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  privateKeyExport(key) {
    const pub = this.publicKeyCreate(key, false);
    const [x, y] = super.publicKeyExport(pub);

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

  publicKeyExport(key) {
    const [x, y] = super.publicKeyExport(key);
    return { x, y };
  }

  publicKeyImport(json, compress) {
    assert(json && typeof json === 'object');
    return super.publicKeyImport(json.x, json.y, json.sign, compress);
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

module.exports = ECDSA;
