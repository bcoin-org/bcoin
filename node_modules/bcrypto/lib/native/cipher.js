/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * CipherBase
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherBase {
  constructor(name, encrypt) {
    const [type, mode] = parseName(name);

    this._handle = binding.cipher_create(type, mode, encrypt);
  }

  init(key, iv) {
    if (iv == null)
      iv = binding.NULL;

    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    binding.cipher_init(this._handle, key, iv);

    return this;
  }

  update(data) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(data));

    const {buffer, length} = binding.cipher_update(this._handle, data);

    return Buffer.from(buffer, 0, length);
  }

  crypt(output, input) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(output));
    assert(Buffer.isBuffer(input));

    return binding.cipher_crypt(this._handle, output, input);
  }

  final() {
    assert(this instanceof CipherBase);
    return binding.cipher_final(this._handle);
  }

  destroy() {
    assert(this instanceof CipherBase);

    binding.cipher_destroy(this._handle);

    return this;
  }

  setAutoPadding(padding) {
    assert(this instanceof CipherBase);
    assert(typeof padding === 'boolean');

    binding.cipher_set_padding(this._handle, padding);

    return this;
  }

  setAAD(data) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(data));

    binding.cipher_set_aad(this._handle, data);

    return this;
  }

  setCCM(msgLen, tagLen, aad) {
    if (aad == null)
      aad = binding.NULL;

    assert(this instanceof CipherBase);
    assert((msgLen >>> 0) === msgLen);
    assert((tagLen >>> 0) === tagLen);
    assert(Buffer.isBuffer(aad));

    binding.cipher_set_ccm(this._handle, msgLen, tagLen, aad);

    return this;
  }

  getAuthTag() {
    assert(this instanceof CipherBase);
    return binding.cipher_get_tag(this._handle);
  }

  setAuthTag(tag) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(tag));

    binding.cipher_set_tag(this._handle, tag);

    return this;
  }
}

/**
 * Cipher
 * @param {String} name
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @param {String} name
 */

class Decipher extends CipherBase {
  constructor(name) {
    super(name, false);
  }
}

/*
 * API
 */

function encrypt(name, key, iv, data) {
  if (iv == null)
    iv = binding.NULL;

  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));
  assert(Buffer.isBuffer(data));

  const [type, mode] = parseName(name);
  const {buffer, length} = binding.cipher_encrypt(type, mode, key, iv, data);

  return Buffer.from(buffer, 0, length);
}

function decrypt(name, key, iv, data) {
  if (iv == null)
    iv = binding.NULL;

  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));
  assert(Buffer.isBuffer(data));

  const [type, mode] = parseName(name);
  const {buffer, length} = binding.cipher_decrypt(type, mode, key, iv, data);

  return Buffer.from(buffer, 0, length);
}

/*
 * Helpers
 */

function parseName(name) {
  assert(typeof name === 'string');

  if (name.substring(0, 3) === 'RC2')
    name = 'A' + name;

  if (binding.algorithms[name] != null) {
    const type = binding.algorithms[name];
    const mode = binding.modes.RAW;

    return [type >>> 0, mode >>> 0];
  }

  if (name.length < 5 || name[name.length - 4] !== '-')
    throw new Error(`Unsupported cipher: ${name}.`);

  const left = name.substring(0, name.length - 4);
  const right = name.substring(name.length - 3);
  const type = binding.algorithms[left];
  const mode = binding.modes[right];

  if (type == null || mode == null || mode === binding.modes.RAW)
    throw new Error(`Unsupported cipher: ${name}.`);

  return [type >>> 0, mode >>> 0];
}

/*
 * Expose
 */

exports.native = 2;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
