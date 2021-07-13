/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const ciphers = require('../internal/ciphers');
const modes = require('./ciphers/modes');
const AES = require('./ciphers/aes');
const Blowfish = require('./ciphers/blowfish');
const Camellia = require('./ciphers/camellia');
const CAST5 = require('./ciphers/cast5');
const {DES, EDE, EDE3} = require('./ciphers/des');
const IDEA = require('./ciphers/idea');
const RC2 = require('./ciphers/rc2');
const Twofish = require('./ciphers/twofish');

/**
 * CipherBase
 */

class CipherBase {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    this.encrypt = encrypt;
    this.ctx = null;
    this._init(name);
  }

  _init(name) {
    assert(typeof name === 'string');

    const info = ciphers.get(name);
    const Mode = modes.get(info.mode, this.encrypt);

    switch (info.algorithm) {
      case 'AES-128':
      case 'AES-192':
      case 'AES-256': {
        const bits = info.keySize * 8;
        this.ctx = new Mode(new AES(bits));
        break;
      }

      case 'BF': {
        this.ctx = new Mode(new Blowfish());
        break;
      }

      case 'CAMELLIA-128':
      case 'CAMELLIA-192':
      case 'CAMELLIA-256': {
        const bits = info.keySize * 8;
        this.ctx = new Mode(new Camellia(bits));
        break;
      }

      case 'CAST5': {
        this.ctx = new Mode(new CAST5());
        break;
      }

      case 'DES': {
        this.ctx = new Mode(new DES());
        break;
      }

      case 'DES-EDE': {
        this.ctx = new Mode(new EDE());
        break;
      }

      case 'DES-EDE3': {
        this.ctx = new Mode(new EDE3());
        break;
      }

      case 'IDEA': {
        this.ctx = new Mode(new IDEA());
        break;
      }

      case 'RC2-64': {
        this.ctx = new Mode(new RC2());
        break;
      }

      case 'TWOFISH-128':
      case 'TWOFISH-192':
      case 'TWOFISH-256': {
        const bits = info.keySize * 8;
        this.ctx = new Mode(new Twofish(bits));
        break;
      }

      default: {
        throw new Error(`Unsupported cipher: ${info.name}.`);
      }
    }
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

  destroy() {
    this.ctx.destroy();
    return this;
  }

  setAAD(data) {
    this.ctx.setAAD(data);
    return this;
  }

  getAuthTag() {
    return this.ctx.getAuthTag();
  }

  setAuthTag(tag) {
    this.ctx.setAuthTag(tag);
    return this;
  }
}

/**
 * Cipher
 * @extends CipherBase
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @extends CipherBase
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
 * Expose
 */

exports.native = 0;
exports._CipherBase = CipherBase;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.info = ciphers.info;
exports.get = ciphers.get;
exports.has = ciphers.has;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
