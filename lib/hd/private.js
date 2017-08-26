/*!
 * private.js - hd private keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const cleanse = require('../crypto/cleanse');
const random = require('../crypto/random');
const secp256k1 = require('../crypto/secp256k1');
const Network = require('../protocol/network');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');
const base58 = require('../utils/base58');
const encoding = require('../utils/encoding');
const common = require('./common');
const Mnemonic = require('./mnemonic');
const HDPublicKey = require('./public');

/*
 * Constants
 */

const SEED_SALT = Buffer.from('Bitcoin seed', 'ascii');

/**
 * HDPrivateKey
 * @alias module:hd.PrivateKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Number?} options.depth
 * @param {Number?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.privateKey
 * @property {Network} network
 * @property {Number} depth
 * @property {Number} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} privateKey
 */

function HDPrivateKey(options) {
  if (!(this instanceof HDPrivateKey))
    return new HDPrivateKey(options);

  this.network = Network.primary;
  this.depth = 0;
  this.parentFingerPrint = 0;
  this.childIndex = 0;
  this.chainCode = encoding.ZERO_HASH;
  this.privateKey = encoding.ZERO_HASH;

  this.publicKey = encoding.ZERO_KEY;
  this.fingerPrint = -1;

  this._xprivkey = null;

  this._hdPublicKey = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

HDPrivateKey.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'No options for HD private key.');
  assert(util.isU8(options.depth));
  assert(util.isU32(options.parentFingerPrint));
  assert(util.isU32(options.childIndex));
  assert(Buffer.isBuffer(options.chainCode));
  assert(Buffer.isBuffer(options.privateKey));

  if (options.network)
    this.network = Network.get(options.network);

  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.privateKey = options.privateKey;
  this.publicKey = secp256k1.publicKeyCreate(options.privateKey, true);

  return this;
};

/**
 * Instantiate HD private key from options object.
 * @param {Object} options
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromOptions = function fromOptions(options) {
  return new HDPrivateKey().fromOptions(options);
};

/**
 * Get HD public key.
 * @returns {HDPublicKey}
 */

HDPrivateKey.prototype.toPublic = function toPublic() {
  let key = this._hdPublicKey;

  if (!key) {
    key = new HDPublicKey();
    key.network = this.network;
    key.depth = this.depth;
    key.parentFingerPrint = this.parentFingerPrint;
    key.childIndex = this.childIndex;
    key.chainCode = this.chainCode;
    key.publicKey = this.publicKey;
    this._hdPublicKey = key;
  }

  return key;
};

/**
 * Get cached base58 xprivkey.
 * @returns {Base58String}
 */

HDPrivateKey.prototype.xprivkey = function xprivkey() {
  if (!this._xprivkey)
    this._xprivkey = this.toBase58();
  return this._xprivkey;
};

/**
 * Get cached base58 xpubkey.
 * @returns {Base58String}
 */

HDPrivateKey.prototype.xpubkey = function xpubkey() {
  return this.toPublic().xpubkey();
};

/**
 * Destroy the key (zeroes chain code, privkey, and pubkey).
 * @param {Boolean} pub - Destroy hd public key as well.
 */

HDPrivateKey.prototype.destroy = function destroy(pub) {
  this.depth = 0;
  this.childIndex = 0;
  this.parentFingerPrint = 0;

  cleanse(this.chainCode);
  cleanse(this.privateKey);
  cleanse(this.publicKey);

  this.fingerPrint = -1;

  if (this._hdPublicKey) {
    if (pub)
      this._hdPublicKey.destroy();
    this._hdPublicKey = null;
  }

  this._xprivkey = null;
};

/**
 * Derive a child key.
 * @param {Number} index - Derivation index.
 * @param {Boolean?} hardened - Whether the derivation should be hardened.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derive = function derive(index, hardened) {
  assert(typeof index === 'number');

  if ((index >>> 0) !== index)
    throw new Error('Index out of range.');

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

  if (hardened) {
    index |= common.HARDENED;
    index >>>= 0;
  }

  const id = this.getID(index);
  const cache = common.cache.get(id);

  if (cache)
    return cache;

  const bw = new StaticWriter(37);

  if (index & common.HARDENED) {
    bw.writeU8(0);
    bw.writeBytes(this.privateKey);
    bw.writeU32BE(index);
  } else {
    bw.writeBytes(this.publicKey);
    bw.writeU32BE(index);
  }

  const data = bw.render();

  const hash = digest.hmac('sha512', data, this.chainCode);
  const left = hash.slice(0, 32);
  const right = hash.slice(32, 64);

  let key;
  try {
    key = secp256k1.privateKeyTweakAdd(this.privateKey, left);
  } catch (e) {
    return this.derive(index + 1);
  }

  if (this.fingerPrint === -1) {
    const fp = digest.hash160(this.publicKey);
    this.fingerPrint = fp.readUInt32BE(0, true);
  }

  const child = new HDPrivateKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = right;
  child.privateKey = key;
  child.publicKey = secp256k1.publicKeyCreate(key, true);

  common.cache.set(id, child);

  return child;
};

/**
 * Unique HD key ID.
 * @private
 * @param {Number} index
 * @returns {String}
 */

HDPrivateKey.prototype.getID = function getID(index) {
  return this.network.keyPrefix.xprivkey58
    + this.publicKey.toString('hex')
    + index;
};

/**
 * Derive a BIP44 account key.
 * @param {Number} purpose
 * @param {Number} account
 * @returns {HDPrivateKey}
 * @throws Error if key is not a master key.
 */

HDPrivateKey.prototype.deriveAccount = function deriveAccount(purpose, account) {
  assert(util.isU32(purpose), 'Purpose must be a number.');
  assert(util.isU32(account), 'Account index must be a number.');
  assert(this.isMaster(), 'Cannot derive account index.');
  return this
    .derive(purpose, true)
    .derive(this.network.keyPrefix.coinType, true)
    .derive(account, true);
};

/**
 * Test whether the key is a master key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isMaster = function isMaster() {
  return common.isMaster(this);
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @param {Number?} account
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isAccount = function isAccount(account) {
  return common.isAccount(this, account);
};

/**
 * Test whether an object is in the form of a base58 xprivkey.
 * @param {String} data
 * @param {Network?} network
 * @returns {Boolean}
 */

HDPrivateKey.isBase58 = function isBase58(data, network) {
  if (typeof data !== 'string')
    return false;

  if (data.length < 4)
    return false;

  const prefix = data.substring(0, 4);

  try {
    Network.fromPrivate58(prefix, network);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Test whether a buffer has a valid network prefix.
 * @param {Buffer} data
 * @param {Network?} network
 * @returns {Boolean}
 */

HDPrivateKey.isRaw = function isRaw(data, network) {
  if (!Buffer.isBuffer(data))
    return false;

  if (data.length < 4)
    return false;

  const version = data.readUInt32BE(0, true);

  try {
    Network.fromPrivate(version, network);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @returns {Boolean}
 */

HDPrivateKey.isValidPath = function isValidPath(path) {
  try {
    common.parsePath(path, true);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Derive a key from a derivation path.
 * @param {String} path
 * @returns {HDPrivateKey}
 * @throws Error if `path` is not a valid path.
 */

HDPrivateKey.prototype.derivePath = function derivePath(path) {
  const indexes = common.parsePath(path, true);

  let key = this;

  for (const index of indexes)
    key = key.derive(index);

  return key;
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.prototype.equals = function equals(obj) {
  assert(HDPrivateKey.isHDPrivateKey(obj));

  return this.network === obj.network
    && this.depth === obj.depth
    && this.parentFingerPrint === obj.parentFingerPrint
    && this.childIndex === obj.childIndex
    && this.chainCode.equals(obj.chainCode)
    && this.privateKey.equals(obj.privateKey);
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.prototype.compare = function compare(key) {
  assert(HDPrivateKey.isHDPrivateKey(key));

  let cmp = this.depth - key.depth;

  if (cmp !== 0)
    return cmp;

  cmp = this.parentFingerPrint - key.parentFingerPrint;

  if (cmp !== 0)
    return cmp;

  cmp = this.childIndex - key.childIndex;

  if (cmp !== 0)
    return cmp;

  cmp = this.chainCode.compare(key.chainCode);

  if (cmp !== 0)
    return cmp;

  cmp = this.privateKey.compare(key.privateKey);

  if (cmp !== 0)
    return cmp;

  return 0;
};

/**
 * Inject properties from seed.
 * @private
 * @param {Buffer} seed
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromSeed = function fromSeed(seed, network) {
  assert(Buffer.isBuffer(seed));

  if (seed.length * 8 < common.MIN_ENTROPY
      || seed.length * 8 > common.MAX_ENTROPY) {
    throw new Error('Entropy not in range.');
  }

  const hash = digest.hmac('sha512', seed, SEED_SALT);
  const left = hash.slice(0, 32);
  const right = hash.slice(32, 64);

  // Only a 1 in 2^127 chance of happening.
  if (!secp256k1.privateKeyVerify(left))
    throw new Error('Master private key is invalid.');

  this.network = Network.get(network);
  this.depth = 0;
  this.parentFingerPrint = 0;
  this.childIndex = 0;
  this.chainCode = right;
  this.privateKey = left;
  this.publicKey = secp256k1.publicKeyCreate(left, true);

  return this;
};

/**
 * Instantiate an hd private key from a 512 bit seed.
 * @param {Buffer} seed
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromSeed = function fromSeed(seed, network) {
  return new HDPrivateKey().fromSeed(seed, network);
};

/**
 * Inject properties from a mnemonic.
 * @private
 * @param {Mnemonic} mnemonic
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromMnemonic = function fromMnemonic(mnemonic, network) {
  assert(mnemonic instanceof Mnemonic);
  return this.fromSeed(mnemonic.toSeed(), network);
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic} mnemonic
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromMnemonic = function fromMnemonic(mnemonic, network) {
  return new HDPrivateKey().fromMnemonic(mnemonic, network);
};

/**
 * Inject properties from a mnemonic.
 * @private
 * @param {String} mnemonic
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromPhrase = function fromPhrase(phrase, network) {
  const mnemonic = Mnemonic.fromPhrase(phrase);
  this.fromMnemonic(mnemonic, network);
  return this;
};

/**
 * Instantiate an hd private key from a phrase.
 * @param {String} phrase
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromPhrase = function fromPhrase(phrase, network) {
  return new HDPrivateKey().fromPhrase(phrase, network);
};

/**
 * Inject properties from privateKey and entropy.
 * @private
 * @param {Buffer} key
 * @param {Buffer} entropy
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromKey = function fromKey(key, entropy, network) {
  assert(Buffer.isBuffer(key) && key.length === 32);
  assert(Buffer.isBuffer(entropy) && entropy.length === 32);
  this.network = Network.get(network);
  this.depth = 0;
  this.parentFingerPrint = 0;
  this.childIndex = 0;
  this.chainCode = entropy;
  this.privateKey = key;
  this.publicKey = secp256k1.publicKeyCreate(key, true);
  return this;
};

/**
 * Create an hd private key from a key and entropy bytes.
 * @param {Buffer} key
 * @param {Buffer} entropy
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromKey = function fromKey(key, entropy, network) {
  return new HDPrivateKey().fromKey(key, entropy, network);
};

/**
 * Generate an hd private key.
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.generate = function generate(network) {
  const key = secp256k1.generatePrivateKey();
  const entropy = random.randomBytes(32);
  return HDPrivateKey.fromKey(key, entropy, network);
};

/**
 * Inject properties from base58 key.
 * @private
 * @param {Base58String} xkey
 * @param {Network?} network
 */

HDPrivateKey.prototype.fromBase58 = function fromBase58(xkey, network) {
  assert(typeof xkey === 'string');
  this._xprivkey = xkey;
  return this.fromRaw(base58.decode(xkey), network);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {BufferReader} br
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromReader = function fromReader(br, network) {
  const version = br.readU32BE();

  this.network = Network.fromPrivate(version, network);
  this.depth = br.readU8();
  this.parentFingerPrint = br.readU32BE();
  this.childIndex = br.readU32BE();
  this.chainCode = br.readBytes(32);
  assert(br.readU8() === 0);
  this.privateKey = br.readBytes(32);
  this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true);

  br.verifyChecksum();

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromRaw = function fromRaw(data, network) {
  return this.fromReader(new BufferReader(data), network);
};

/**
 * Serialize key to a base58 string.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

HDPrivateKey.prototype.toBase58 = function toBase58(network) {
  return base58.encode(this.toRaw(network));
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

HDPrivateKey.prototype.getSize = function getSize() {
  return 82;
};

/**
 * Write the key to a buffer writer.
 * @param {BufferWriter} bw
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.toWriter = function toWriter(bw, network) {
  if (!network)
    network = this.network;

  network = Network.get(network);

  bw.writeU32BE(network.keyPrefix.xprivkey);
  bw.writeU8(this.depth);
  bw.writeU32BE(this.parentFingerPrint);
  bw.writeU32BE(this.childIndex);
  bw.writeBytes(this.chainCode);
  bw.writeU8(0);
  bw.writeBytes(this.privateKey);
  bw.writeChecksum();

  return bw;
};

/**
 * Serialize the key.
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPrivateKey.prototype.toRaw = function toRaw(network) {
  return this.toWriter(new StaticWriter(82), network).render();
};

/**
 * Instantiate an HD private key from a base58 string.
 * @param {Base58String} xkey
 * @param {Network?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromBase58 = function fromBase58(xkey, network) {
  return new HDPrivateKey().fromBase58(xkey, network);
};

/**
 * Instantiate key from buffer reader.
 * @param {BufferReader} br
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromReader = function fromReader(br, network) {
  return new HDPrivateKey().fromReader(br, network);
};

/**
 * Instantiate key from serialized data.
 * @param {Buffer} data
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromRaw = function fromRaw(data, network) {
  return new HDPrivateKey().fromRaw(data, network);
};

/**
 * Convert key to a more json-friendly object.
 * @returns {Object}
 */

HDPrivateKey.prototype.toJSON = function toJSON() {
  return {
    xprivkey: this.xprivkey()
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @param {Network?} network
 */

HDPrivateKey.prototype.fromJSON = function fromJSON(json, network) {
  assert(json.xprivkey, 'Could not handle key JSON.');

  this.fromBase58(json.xprivkey, network);

  return this;
};

/**
 * Instantiate an HDPrivateKey from a jsonified key object.
 * @param {Object} json - The jsonified key object.
 * @param {Network?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromJSON = function fromJSON(json, network) {
  return new HDPrivateKey().fromJSON(json, network);
};

/**
 * Test whether an object is an HDPrivateKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.isHDPrivateKey = function isHDPrivateKey(obj) {
  return obj
    && typeof obj.derive === 'function'
    && typeof obj.fromMnemonic === 'function'
    && Buffer.isBuffer(obj.chainCode);
};

/*
 * Expose
 */

module.exports = HDPrivateKey;
