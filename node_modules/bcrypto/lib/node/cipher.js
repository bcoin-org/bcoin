/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint new-cap: "off" */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const ciphers = require('../internal/ciphers');

/**
 * CipherBase
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherBase {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    this.name = name;
    this.encrypt = encrypt;
    this.ctx = null;
  }

  init(key, iv) {
    assert(Buffer.isBuffer(key));
    assert(!iv || Buffer.isBuffer(iv));

    // Older versions of
    // node.js throw on `null`.
    if (iv == null)
      iv = Buffer.alloc(0);

    this.ctx = this.encrypt
      ? crypto.createCipheriv(this.name, key, iv)
      : crypto.createDecipheriv(this.name, key, iv);

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx);
    return this.ctx.update(data);
  }

  final() {
    assert(this.ctx);
    return this.ctx.final();
  }

  setAAD(data) {
    assert(this.ctx);
    this.ctx.setAAD(data);
    return this;
  }

  getAuthTag() {
    assert(this.ctx);
    assert(this.encrypt);
    return this.ctx.getAuthTag();
  }

  setAuthTag(tag) {
    assert(this.ctx);
    assert(!this.encrypt);
    this.ctx.setAuthTag(tag);
    return this;
  }
}

/**
 * CipherWrap
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherWrap {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    this.ctx = null;

    if (hasCipher(name))
      this.ctx = new CipherBase(name, encrypt);
    else
      this.ctx = fallback(name, encrypt);
  }

  init(key, iv) {
    this.ctx.init(key, iv);
    return this;
  }

  update(data) {
    return this.ctx.update(data);
  }

  final() {
    return this.ctx.final();
  }

  setAAD(data) {
    assert(this.ctx);
    this.ctx.setAAD(data);
    return this;
  }

  getAuthTag() {
    assert(this.ctx);
    return this.ctx.getAuthTag();
  }

  setAuthTag(tag) {
    assert(this.ctx);
    this.ctx.setAuthTag(tag);
    return this;
  }
}

/**
 * Cipher
 * @param {String} name
 */

class Cipher extends CipherWrap {
  constructor(name) {
    if (!ciphers.has(name))
      throw new Error('Unsupported cipher.');
    super(name, true);
  }
}

/**
 * Decipher
 * @param {String} name
 */

class Decipher extends CipherWrap {
  constructor(name) {
    if (!ciphers.has(name))
      throw new Error('Unsupported cipher.');
    super(name, false);
  }
}

/*
 * API
 */

function encrypt(name, key, iv, data) {
  const ctx = new Cipher(name);
  ctx.init(key, iv);
  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

function decrypt(name, key, iv, data) {
  const ctx = new Decipher(name);
  ctx.init(key, iv);
  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

/*
 * Helpers
 */

let fb = null;
let list = null;

function hasCipher(name) {
  if (!list) {
    list = new Set();

    for (const cipher of crypto.getCiphers())
      list.add(cipher.toUpperCase());
  }

  return list.has(name);
}

function fallback(name, encrypt) {
  if (!fb)
    fb = require('../js/cipher');
  return new fb._CipherBase(name, encrypt);
}

/*
 * Expose
 */

exports.native = 1;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.info = ciphers.info;
exports.get = ciphers.get;
exports.has = ciphers.has;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
