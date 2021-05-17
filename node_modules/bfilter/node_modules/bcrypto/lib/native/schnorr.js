/*!
 * schnorr.js - schnorr wrapper for libtorsion
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Schnorr
 */

class Schnorr extends binding.Schnorr {
  constructor(name) {
    super(binding.curves.ecdsa[name]);

    this.id = name;
    this.type = 'schnorr';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;

    this._randomize(binding.entropy());
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  privateKeyExport(key) {
    const [d, x, y] = super.privateKeyExport(key);
    return { d, x, y };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    return super.privateKeyImport(json.d);
  }

  publicKeyExport(key) {
    const [x, y] = super.publicKeyExport(key);
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

  sign(msg, key, aux = binding.entropy(32)) {
    return super.sign(msg, key, aux);
  }
}

/*
 * Expose
 */

module.exports = new Schnorr('SECP256K1');
