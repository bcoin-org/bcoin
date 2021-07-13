/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const modes = require('./ciphers/modes');
const AES = require('./ciphers/aes');
const ARC2 = require('./ciphers/arc2');
const Blowfish = require('./ciphers/blowfish');
const Camellia = require('./ciphers/camellia');
const CAST5 = require('./ciphers/cast5');
const {DES, EDE, EDE3} = require('./ciphers/des');
const IDEA = require('./ciphers/idea');
const Serpent = require('./ciphers/serpent');
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
    const [algo, mode] = parseName(name);
    const Mode = modes.get(mode, this.encrypt);

    switch (algo) {
      case 'AES-128':
      case 'AES-192':
      case 'AES-256': {
        const bits = algo.slice(-3) | 0;
        this.ctx = new Mode(new AES(bits));
        break;
      }

      case 'ARC2': {
        this.ctx = new Mode(new ARC2());
        break;
      }

      case 'ARC2-GUTMANN': {
        this.ctx = new Mode(new ARC2(-1, 0));
        break;
      }

      case 'ARC2-40': {
        this.ctx = new Mode(new ARC2(40));
        break;
      }

      case 'ARC2-64': {
        this.ctx = new Mode(new ARC2(64));
        break;
      }

      case 'ARC2-128': {
        this.ctx = new Mode(new ARC2(128));
        break;
      }

      case 'ARC2-128-GUTMANN': {
        this.ctx = new Mode(new ARC2(128, 1024));
        break;
      }

      case 'BF':
      case 'BLOWFISH': {
        this.ctx = new Mode(new Blowfish());
        break;
      }

      case 'CAMELLIA-128':
      case 'CAMELLIA-192':
      case 'CAMELLIA-256': {
        const bits = algo.slice(-3) | 0;
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

      case 'SERPENT-128':
      case 'SERPENT-192':
      case 'SERPENT-256': {
        const bits = algo.slice(-3) | 0;
        this.ctx = new Mode(new Serpent(bits));
        break;
      }

      case 'TWOFISH-128':
      case 'TWOFISH-192':
      case 'TWOFISH-256': {
        const bits = algo.slice(-3) | 0;
        this.ctx = new Mode(new Twofish(bits));
        break;
      }

      default: {
        throw new Error(`Unsupported cipher: ${name}.`);
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

  crypt(output, input) {
    return this.ctx.crypt(output, input);
  }

  final() {
    return this.ctx.final();
  }

  destroy() {
    this.ctx.destroy();
    return this;
  }

  setAutoPadding(padding) {
    this.ctx.setAutoPadding(padding);
    return this;
  }

  setAAD(data) {
    this.ctx.setAAD(data);
    return this;
  }

  setCCM(msgLen, tagLen, aad) {
    this.ctx.setCCM(msgLen, tagLen, aad);
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
 * Helpers
 */

const modeNames = {
  __proto__: null,
  ECB: true,
  CBC: true,
  CTS: true,
  XTS: true,
  CTR: true,
  CFB: true,
  OFB: true,
  GCM: true,
  CCM: true,
  EAX: true
};

function parseName(name) {
  assert(typeof name === 'string');

  if (name.substring(0, 3) === 'RC2')
    name = 'A' + name;

  if (name.length < 5)
    return [name, 'RAW'];

  const mode = name.substring(name.length - 3);

  if (name[name.length - 4] !== '-' || !modeNames[mode])
    return [name, 'RAW'];

  const algo = name.substring(0, name.length - 4);

  return [algo, mode];
}

/*
 * Expose
 */

exports.native = 0;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
