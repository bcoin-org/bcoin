/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {assert, enforce} = require('bsert');
const ChaCha20 = require('./chacha20');
const Poly1305 = require('./poly1305');

/**
 * AEAD
 * @see https://github.com/openssh/openssh-portable
 * @see https://tools.ietf.org/html/rfc7539#section-2.8
 */

class AEAD {
  /**
   * Create an AEAD context.
   * @constructor
   */

  constructor() {
    this.chacha20 = new ChaCha20();
    this.poly1305 = new Poly1305();
    this.aadLen = 0;
    this.cipherLen = 0;
    this.hasCipher = false;
    this.polyKey = null;
  }

  /**
   * Initialize the AEAD with a key and iv.
   * @param {Buffer} key
   * @param {Buffer} iv - IV / packet sequence number.
   */

  init(key, iv) {
    enforce(Buffer.isBuffer(key), 'key', 'buffer');
    enforce(Buffer.isBuffer(iv), 'iv', 'buffer');

    const polyKey = Buffer.alloc(32, 0x00);

    this.chacha20.init(key, iv, 0);
    this.chacha20.encrypt(polyKey);
    this.poly1305.init(polyKey);

    // We need to encrypt a full block
    // to get the cipher in the correct state.
    this.chacha20.encrypt(Buffer.alloc(32, 0x00));

    // Counter should be one.
    if (iv.length !== 16)
      assert(this.chacha20.getCounter() === 1);

    // Expose for debugging.
    this.polyKey = polyKey;

    this.aadLen = 0;
    this.cipherLen = 0;
    this.hasCipher = false;

    return this;
  }

  /**
   * Update the aad (will be finalized
   * on an encrypt/decrypt call).
   * @param {Buffer} aad
   */

  aad(data) {
    assert(!this.hasCipher, 'Cannot update aad.');
    this.poly1305.update(data);
    this.aadLen += data.length;
    return this;
  }

  /**
   * Encrypt a piece of data.
   * @param {Buffer} data
   */

  encrypt(data) {
    if (!this.hasCipher)
      this._pad16(this.aadLen);

    this.chacha20.encrypt(data);
    this.poly1305.update(data);

    this.cipherLen += data.length;
    this.hasCipher = true;

    return data;
  }

  /**
   * Decrypt a piece of data.
   * @param {Buffer} data
   */

  decrypt(data) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');

    if (!this.hasCipher)
      this._pad16(this.aadLen);

    this.cipherLen += data.length;
    this.hasCipher = true;

    this.poly1305.update(data);
    this.chacha20.encrypt(data);

    return data;
  }

  /**
   * Authenticate data without decrypting.
   * @param {Buffer} data
   */

  auth(data) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');

    if (!this.hasCipher)
      this._pad16(this.aadLen);

    this.cipherLen += data.length;
    this.hasCipher = true;

    this.poly1305.update(data);

    return data;
  }

  /**
   * Finalize the aead and generate a MAC.
   * @returns {Buffer} MAC
   */

  final() {
    const len = Buffer.allocUnsafe(16);

    let lo, hi;

    // The RFC says these are supposed to be
    // uint32le, but their own fucking test
    // cases fail unless they are uint64le's.
    lo = this.aadLen % 0x100000000;
    hi = (this.aadLen - lo) / 0x100000000;
    writeU32(len, lo, 0);
    writeU32(len, hi, 4);

    lo = this.cipherLen % 0x100000000;
    hi = (this.cipherLen - lo) / 0x100000000;
    writeU32(len, lo, 8);
    writeU32(len, hi, 12);

    if (!this.hasCipher)
      this._pad16(this.aadLen);

    this._pad16(this.cipherLen);
    this.poly1305.update(len);

    return this.poly1305.final();
  }

  /**
   * Pad a chunk before updating mac.
   * @private
   * @param {Number} size
   */

  _pad16(size) {
    size %= 16;

    if (size === 0)
      return;

    const pad = Buffer.allocUnsafe(16 - size);
    pad.fill(0);

    this.poly1305.update(pad);
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

    return AEAD.verify(aead.final(), tag);
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

    return AEAD.verify(aead.final(), tag);
  }

  /**
   * Compare two MACs in constant time.
   * @param {Buffer} mac1
   * @param {Buffer} mac2
   * @returns {Boolean}
   */

  static verify(mac1, mac2) {
    return Poly1305.verify(mac1, mac2);
  }
}

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

/*
 * Expose
 */

module.exports = AEAD;
