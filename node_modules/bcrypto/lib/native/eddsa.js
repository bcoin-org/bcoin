/*!
 * eddsa.js - EdDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * EDDSA
 */

class EDDSA extends binding.EDDSA {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'eddsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;

    this._randomize(binding.entropy());
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  scalarGenerate() {
    return super.scalarGenerate(binding.entropy());
  }

  privateKeyExport(secret) {
    const pub = this.publicKeyCreate(secret);
    const [x, y] = super.publicKeyExport(pub);

    return {
      d: Buffer.from(secret),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    return super.privateKeyImport(json.d);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    return super.publicKeyToUniform(key, hint);
  }

  publicKeyExport(key) {
    const [x, y] = super.publicKeyExport(key);
    return { x, y };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');
    return super.publicKeyImport(json.x, json.y, json.sign);
  }

  publicKeyToHash(key) {
    return super.publicKeyToHash(key, binding.entropy());
  }
}

/*
 * Expose
 */

module.exports = EDDSA;
