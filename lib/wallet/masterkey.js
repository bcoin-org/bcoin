/*!
 * masterkey.js - master bip32 key object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const Lock = require('../utils/lock');
const random = require('../crypto/random');
const cleanse = require('../crypto/cleanse');
const aes = require('../crypto/aes');
const pbkdf2 = require('../crypto/pbkdf2');
const scrypt = require('../crypto/scrypt');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
const HD = require('../hd/hd');
const Mnemonic = HD.Mnemonic;

/**
 * Master BIP32 key which can exist
 * in a timed out encrypted state.
 * @alias module:wallet.MasterKey
 * @constructor
 * @param {Object} options
 */

function MasterKey(options) {
  if (!(this instanceof MasterKey))
    return new MasterKey(options);

  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;
  this.key = null;
  this.mnemonic = null;

  this.alg = MasterKey.alg.PBKDF2;
  this.N = 50000;
  this.r = 0;
  this.p = 0;

  this.aesKey = null;
  this.timer = null;
  this.until = 0;
  this._onTimeout = this.lock.bind(this);
  this.locker = new Lock();

  if (options)
    this.fromOptions(options);
}

/**
 * Key derivation salt.
 * @const {Buffer}
 * @default
 */

MasterKey.SALT = Buffer.from('bcoin', 'ascii');

/**
 * Key derivation algorithms.
 * @enum {Number}
 * @default
 */

MasterKey.alg = {
  PBKDF2: 0,
  SCRYPT: 1
};

/**
 * Key derivation algorithms by value.
 * @enum {String}
 * @default
 */

MasterKey.algByVal = {
  0: 'PBKDF2',
  1: 'SCRYPT'
};

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MasterKey.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.encrypted != null) {
    assert(typeof options.encrypted === 'boolean');
    this.encrypted = options.encrypted;
  }

  if (options.iv) {
    assert(Buffer.isBuffer(options.iv));
    this.iv = options.iv;
  }

  if (options.ciphertext) {
    assert(Buffer.isBuffer(options.ciphertext));
    this.ciphertext = options.ciphertext;
  }

  if (options.key) {
    assert(HD.isPrivate(options.key));
    this.key = options.key;
  }

  if (options.mnemonic) {
    assert(options.mnemonic instanceof Mnemonic);
    this.mnemonic = options.mnemonic;
  }

  if (options.alg != null) {
    if (typeof options.alg === 'string') {
      this.alg = MasterKey.alg[options.alg.toUpperCase()];
      assert(this.alg != null, 'Unknown algorithm.');
    } else {
      assert(typeof options.alg === 'number');
      assert(MasterKey.algByVal[options.alg]);
      this.alg = options.alg;
    }
  }

  if (options.rounds != null) {
    assert(util.isNumber(options.rounds));
    this.N = options.rounds;
  }

  if (options.N != null) {
    assert(util.isNumber(options.N));
    this.N = options.N;
  }

  if (options.r != null) {
    assert(util.isNumber(options.r));
    this.r = options.r;
  }

  if (options.p != null) {
    assert(util.isNumber(options.p));
    this.p = options.p;
  }

  assert(this.encrypted ? !this.key : this.key);

  return this;
};

/**
 * Instantiate master key from options.
 * @returns {MasterKey}
 */

MasterKey.fromOptions = function fromOptions(options) {
  return new MasterKey().fromOptions(options);
};

/**
 * Decrypt the key and set a timeout to destroy decrypted data.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @returns {Promise} - Returns {@link HDPrivateKey}.
 */

MasterKey.prototype.unlock = async function _unlock(passphrase, timeout) {
  let unlock = await this.locker.lock();
  try {
    return await this._unlock(passphrase, timeout);
  } finally {
    unlock();
  }
};

/**
 * Decrypt the key without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @param {Number} [timeout=60000] timeout in ms.
 * @returns {Promise} - Returns {@link HDPrivateKey}.
 */

MasterKey.prototype._unlock = async function _unlock(passphrase, timeout) {
  let data, key;

  if (this.key) {
    if (this.encrypted) {
      assert(this.timer != null);
      this.start(timeout);
    }
    return this.key;
  }

  if (!passphrase)
    throw new Error('No passphrase.');

  assert(this.encrypted);

  key = await this.derive(passphrase);
  data = aes.decipher(this.ciphertext, key, this.iv);

  this.fromKeyRaw(data);

  this.start(timeout);

  this.aesKey = key;

  return this.key;
};

/**
 * Start the destroy timer.
 * @private
 * @param {Number} [timeout=60000] timeout in ms.
 */

MasterKey.prototype.start = function start(timeout) {
  if (!timeout)
    timeout = 60;

  this.stop();

  if (timeout === -1)
    return;

  this.until = util.now() + timeout;
  this.timer = setTimeout(this._onTimeout, timeout * 1000);
};

/**
 * Stop the destroy timer.
 * @private
 */

MasterKey.prototype.stop = function stop() {
  if (this.timer != null) {
    clearTimeout(this.timer);
    this.timer = null;
    this.until = 0;
  }
};

/**
 * Derive an aes key based on params.
 * @param {String|Buffer} passphrase
 * @returns {Promise}
 */

MasterKey.prototype.derive = async function derive(passwd) {
  let salt = MasterKey.SALT;
  let N = this.N;
  let r = this.r;
  let p = this.p;

  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  switch (this.alg) {
    case MasterKey.alg.PBKDF2:
      return await pbkdf2.deriveAsync(passwd, salt, N, 32, 'sha256');
    case MasterKey.alg.SCRYPT:
      return await scrypt.deriveAsync(passwd, salt, N, r, p, 32);
    default:
      throw new Error(`Unknown algorithm: ${this.alg}.`);
  }
};

/**
 * Encrypt data with in-memory aes key.
 * @param {Buffer} data
 * @param {Buffer} iv
 * @returns {Buffer}
 */

MasterKey.prototype.encipher = function encipher(data, iv) {
  if (!this.aesKey)
    return;

  if (typeof iv === 'string')
    iv = Buffer.from(iv, 'hex');

  return aes.encipher(data, this.aesKey, iv.slice(0, 16));
};

/**
 * Decrypt data with in-memory aes key.
 * @param {Buffer} data
 * @param {Buffer} iv
 * @returns {Buffer}
 */

MasterKey.prototype.decipher = function decipher(data, iv) {
  if (!this.aesKey)
    return;

  if (typeof iv === 'string')
    iv = Buffer.from(iv, 'hex');

  return aes.decipher(data, this.aesKey, iv.slice(0, 16));
};

/**
 * Destroy the key by zeroing the
 * privateKey and chainCode. Stop
 * the timer if there is one.
 * @returns {Promise}
 */

MasterKey.prototype.lock = async function _lock() {
  let unlock = await this.locker.lock();
  try {
    return await this._lock();
  } finally {
    unlock();
  }
};

/**
 * Destroy the key by zeroing the
 * privateKey and chainCode. Stop
 * the timer if there is one.
 */

MasterKey.prototype._lock = function lock() {
  if (!this.encrypted) {
    assert(this.timer == null);
    assert(this.key);
    return;
  }

  this.stop();

  if (this.key) {
    this.key.destroy(true);
    this.key = null;
  }

  if (this.aesKey) {
    cleanse(this.aesKey);
    this.aesKey = null;
  }
};

/**
 * Destroy the key permanently.
 */

MasterKey.prototype.destroy = async function destroy() {
  await this.lock();
  this.locker.destroy();
};

/**
 * Decrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype.decrypt = async function decrypt(passphrase, clean) {
  let unlock = await this.locker.lock();
  try {
    return await this._decrypt(passphrase, clean);
  } finally {
    unlock();
  }
};

/**
 * Decrypt the key permanently without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype._decrypt = async function decrypt(passphrase, clean) {
  let key, data;

  if (!this.encrypted)
    throw new Error('Master key is not encrypted.');

  if (!passphrase)
    throw new Error('No passphrase provided.');

  this._lock();

  key = await this.derive(passphrase);
  data = aes.decipher(this.ciphertext, key, this.iv);

  this.fromKeyRaw(data);
  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;

  if (!clean) {
    cleanse(key);
    return;
  }

  return key;
};

/**
 * Encrypt the key permanently.
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype.encrypt = async function encrypt(passphrase, clean) {
  let unlock = await this.locker.lock();
  try {
    return await this._encrypt(passphrase, clean);
  } finally {
    unlock();
  }
};

/**
 * Encrypt the key permanently without a lock.
 * @private
 * @param {Buffer|String} passphrase - Zero this yourself.
 * @returns {Promise}
 */

MasterKey.prototype._encrypt = async function encrypt(passphrase, clean) {
  let key, data, iv;

  if (this.encrypted)
    throw new Error('Master key is already encrypted.');

  if (!passphrase)
    throw new Error('No passphrase provided.');

  data = this.toKeyRaw();
  iv = random.randomBytes(16);

  this.stop();

  key = await this.derive(passphrase);
  data = aes.encipher(data, key, iv);

  this.key = null;
  this.mnemonic = null;
  this.encrypted = true;
  this.iv = iv;
  this.ciphertext = data;

  if (!clean) {
    cleanse(key);
    return;
  }

  return key;
};

/**
 * Calculate key serialization size.
 * @returns {Number}
 */

MasterKey.prototype.getKeySize = function getKeySize() {
  let size = 0;

  size += this.key.getSize();
  size += 1;

  if (this.mnemonic)
    size += this.mnemonic.getSize();

  return size;
};

/**
 * Serialize key and menmonic to a single buffer.
 * @returns {Buffer}
 */

MasterKey.prototype.toKeyRaw = function toKeyRaw() {
  let bw = new StaticWriter(this.getKeySize());

  this.key.toWriter(bw);

  if (this.mnemonic) {
    bw.writeU8(1);
    this.mnemonic.toWriter(bw);
  } else {
    bw.writeU8(0);
  }

  return bw.render();
};

/**
 * Inject properties from serialized key.
 * @param {Buffer} data
 */

MasterKey.prototype.fromKeyRaw = function fromKeyRaw(data) {
  let br = new BufferReader(data);

  this.key = HD.PrivateKey.fromReader(br);

  if (br.readU8() === 1)
    this.mnemonic = Mnemonic.fromReader(br);

  return this;
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

MasterKey.prototype.getSize = function getSize() {
  let size = 0;

  if (this.encrypted) {
    size += 1;
    size += encoding.sizeVarBytes(this.iv);
    size += encoding.sizeVarBytes(this.ciphertext);
    size += 13;
    return size;
  }

  size += 1;
  size += encoding.sizeVarlen(this.getKeySize());

  return size;
};

/**
 * Serialize the key in the form of:
 * `[enc-flag][iv?][ciphertext?][extended-key?]`
 * @returns {Buffer}
 */

MasterKey.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  if (this.encrypted) {
    bw.writeU8(1);
    bw.writeVarBytes(this.iv);
    bw.writeVarBytes(this.ciphertext);

    bw.writeU8(this.alg);
    bw.writeU32(this.N);
    bw.writeU32(this.r);
    bw.writeU32(this.p);

    return bw.render();
  }

  bw.writeU8(0);

  // NOTE: useless varint
  size = this.getKeySize();
  bw.writeVarint(size);

  bw.writeBytes(this.key.toRaw());

  if (this.mnemonic) {
    bw.writeU8(1);
    this.mnemonic.toWriter(bw);
  } else {
    bw.writeU8(0);
  }

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

MasterKey.prototype.fromRaw = function fromRaw(raw) {
  let br = new BufferReader(raw);

  this.encrypted = br.readU8() === 1;

  if (this.encrypted) {
    this.iv = br.readVarBytes();
    this.ciphertext = br.readVarBytes();

    this.alg = br.readU8();

    assert(MasterKey.algByVal[this.alg]);

    this.N = br.readU32();
    this.r = br.readU32();
    this.p = br.readU32();

    return this;
  }

  // NOTE: useless varint
  br.skipVarint();

  this.key = HD.PrivateKey.fromRaw(br.readBytes(82));

  if (br.readU8() === 1)
    this.mnemonic = Mnemonic.fromReader(br);

  return this;
};

/**
 * Instantiate master key from serialized data.
 * @returns {MasterKey}
 */

MasterKey.fromRaw = function fromRaw(raw) {
  return new MasterKey().fromRaw(raw);
};

/**
 * Inject properties from an HDPrivateKey.
 * @private
 * @param {HDPrivateKey} key
 * @param {Mnemonic?} mnemonic
 */

MasterKey.prototype.fromKey = function fromKey(key, mnemonic) {
  this.encrypted = false;
  this.iv = null;
  this.ciphertext = null;
  this.key = key;
  this.mnemonic = mnemonic || null;
  return this;
};

/**
 * Instantiate master key from an HDPrivateKey.
 * @param {HDPrivateKey} key
 * @param {Mnemonic?} mnemonic
 * @returns {MasterKey}
 */

MasterKey.fromKey = function fromKey(key, mnemonic) {
  return new MasterKey().fromKey(key, mnemonic);
};

/**
 * Convert master key to a jsonifiable object.
 * @param {Boolean?} unsafe - Whether to include
 * the key data in the JSON.
 * @returns {Object}
 */

MasterKey.prototype.toJSON = function toJSON(unsafe) {
  if (this.encrypted) {
    return {
      encrypted: true,
      until: this.until,
      iv: this.iv.toString('hex'),
      ciphertext: unsafe ? this.ciphertext.toString('hex') : undefined,
      algorithm: MasterKey.algByVal[this.alg].toLowerCase(),
      N: this.N,
      r: this.r,
      p: this.p
    };
  }

  return {
    encrypted: false,
    key: unsafe ? this.key.toJSON() : undefined,
    mnemonic: unsafe && this.mnemonic ? this.mnemonic.toJSON() : undefined
  };
};

/**
 * Inspect the key.
 * @returns {Object}
 */

MasterKey.prototype.inspect = function inspect() {
  let json = this.toJSON(true);

  if (this.key)
    json.key = this.key.toJSON();

  if (this.mnemonic)
    json.mnemonic = this.mnemonic.toJSON();

  return json;
};

/**
 * Test whether an object is a MasterKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

MasterKey.isMasterKey = function isMasterKey(obj) {
  return obj
    && typeof obj.encrypted === 'boolean'
    && typeof obj.decrypt === 'function';
};

/*
 * Expose
 */

module.exports = MasterKey;
