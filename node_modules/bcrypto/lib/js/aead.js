/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7539#section-2.8
 *   https://github.com/openssh/openssh-portable
 */

'use strict';

const assert = require('../internal/assert');
const ChaCha20 = require('./chacha20');
const Poly1305 = require('./poly1305');

/*
 * Constants
 */

const zero16 = Buffer.alloc(16, 0x00);

/**
 * AEAD
 */

class AEAD {
  /**
   * Create an AEAD context.
   * @constructor
   */

  constructor() {
    this.chacha = new ChaCha20();
    this.poly = new Poly1305();
    this.key = Buffer.alloc(64);
    this.mode = -1;
    this.aadLen = 0;
    this.cipherLen = 0;
  }

  /**
   * Initialize the AEAD with a key and iv.
   * @param {Buffer} key
   * @param {Buffer} iv - IV / packet sequence number.
   */

  init(key, iv) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    this.key.fill(0);
    this.chacha.init(key, iv, 0);
    this.chacha.encrypt(this.key);
    this.poly.init(this.key);

    this.mode = 0;
    this.aadLen = 0;
    this.cipherLen = 0;

    return this;
  }

  /**
   * Update the aad (will be finalized
   * on an encrypt/decrypt call).
   * @param {Buffer} aad
   */

  aad(data) {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0)
      throw new Error('Invalid state for aad.');

    this.poly.update(data);
    this.aadLen += data.length;

    return this;
  }

  /**
   * Encrypt a piece of data.
   * @param {Buffer} data
   */

  encrypt(data) {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 1)
      throw new Error('Invalid state for encrypt.');

    if (this.mode === 0) {
      this._pad16(this.aadLen);
      this.mode = 1;
    }

    this.chacha.encrypt(data);
    this.poly.update(data);

    this.cipherLen += data.length;

    return data;
  }

  /**
   * Decrypt a piece of data.
   * @param {Buffer} data
   */

  decrypt(data) {
    assert(Buffer.isBuffer(data));

    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 2)
      throw new Error('Invalid state for decrypt.');

    if (this.mode === 0) {
      this._pad16(this.aadLen);
      this.mode = 2;
    }

    this.cipherLen += data.length;

    this.poly.update(data);
    this.chacha.encrypt(data);

    return data;
  }

  /**
   * Authenticate data without decrypting.
   * @param {Buffer} data
   */

  auth(data) {
    assert(Buffer.isBuffer(data));

    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    if (this.mode !== 0 && this.mode !== 3)
      throw new Error('Invalid state for auth.');

    if (this.mode === 0) {
      this._pad16(this.aadLen);
      this.mode = 3;
    }

    this.cipherLen += data.length;

    this.poly.update(data);

    return data;
  }

  /**
   * Finalize the aead and generate a MAC.
   * @returns {Buffer} MAC
   */

  final() {
    if (this.mode === -1)
      throw new Error('Context is not initialized.');

    const len = Buffer.alloc(16);

    writeU64(len, this.aadLen, 0);
    writeU64(len, this.cipherLen, 8);

    if (this.mode === 0)
      this._pad16(this.aadLen);

    this._pad16(this.cipherLen);
    this.poly.update(len);

    const mac = this.poly.final();

    this.destroy();

    return mac;
  }

  /**
   * Destroy the context.
   */

  destroy() {
    this.chacha.destroy();
    this.poly.destroy();

    for (let i = 0; i < 64; i++)
      this.key[i] = 0;

    this.mode = -1;
    this.aadLen = 0;
    this.cipherLen = 0;

    return this;
  }

  /**
   * Finalize and verify MAC against tag.
   * @param {Buffer} tag
   * @returns {Boolean}
   */

  verify(tag) {
    assert(Buffer.isBuffer(tag));
    assert(tag.length === 16);

    const mac = this.final();

    let z = 0;

    for (let i = 0; i < 16; i++)
      z |= mac[i] ^ tag[i];

    return ((z - 1) >>> 31) !== 0;
  }

  /**
   * Pad a chunk before updating mac.
   * @private
   * @param {Number} size
   */

  _pad16(size) {
    const pos = size & 15;

    if (pos > 0)
      this.poly.update(zero16.slice(0, 16 - pos));
  }

  /**
   * Encrypt a piece of data.
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer?} aad
   * @returns {Buffer} tag
   */

  static encrypt(key, iv, msg, aad) {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.encrypt(msg);

    return aead.final();
  }

  /**
   * Decrypt a piece of data.
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer} tag
   * @param {Buffer?} aad
   * @returns {Boolean}
   */

  static decrypt(key, iv, msg, tag, aad) {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.decrypt(msg);

    return aead.verify(tag);
  }

  /**
   * Authenticate data without decrypting.
   * @param {Buffer} key
   * @param {Buffer} iv
   * @param {Buffer} msg
   * @param {Buffer} tag
   * @param {Buffer?} aad
   * @returns {Boolean}
   */

  static auth(key, iv, msg, tag, aad) {
    const aead = new AEAD();

    aead.init(key, iv);

    if (aad)
      aead.aad(aad);

    aead.auth(msg);

    return aead.verify(tag);
  }
}

/*
 * Static
 */

AEAD.native = ChaCha20.native;

/*
 * Helpers
 */

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

function writeU64(dst, num, off) {
  const hi = (num * (1 / 0x100000000)) >>> 0;
  const lo = num >>> 0;

  writeU32(dst, lo, off + 0);
  writeU32(dst, hi, off + 4);

  return off + 8;
}

/*
 * Expose
 */

module.exports = AEAD;
