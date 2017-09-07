/*!
 * public.js - hd public keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const cleanse = require('../crypto/cleanse');
const secp256k1 = require('../crypto/secp256k1');
const Network = require('../protocol/network');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');
const base58 = require('../utils/base58');
const encoding = require('../utils/encoding');
const common = require('./common');

/**
 * HDPublicKey
 * @alias module:hd.PublicKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Number?} options.depth
 * @param {Number?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.publicKey
 * @property {Network} network
 * @property {Number} depth
 * @property {Number} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} publicKey
 */

function HDPublicKey(options) {
  if (!(this instanceof HDPublicKey))
    return new HDPublicKey(options);

  this.network = Network.primary;
  this.depth = 0;
  this.parentFingerPrint = 0;
  this.childIndex = 0;
  this.chainCode = encoding.ZERO_HASH;
  this.publicKey = encoding.ZERO_KEY;

  this.fingerPrint = -1;

  this._xpubkey = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

HDPublicKey.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'No options for HDPublicKey');
  assert(util.isU8(options.depth));
  assert(util.isU32(options.parentFingerPrint));
  assert(util.isU32(options.childIndex));
  assert(Buffer.isBuffer(options.chainCode));
  assert(Buffer.isBuffer(options.publicKey));

  if (options.network)
    this.network = Network.get(options.network);

  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.publicKey = options.publicKey;

  return this;
};

/**
 * Instantiate HD public key from options object.
 * @param {Object} options
 * @returns {HDPublicKey}
 */

HDPublicKey.fromOptions = function fromOptions(options) {
  return new HDPublicKey().fromOptions(options);
};

/**
 * Get HD public key (self).
 * @returns {HDPublicKey}
 */

HDPublicKey.prototype.toPublic = function toPublic() {
  return this;
};

/**
 * Get cached base58 xprivkey (always null here).
 * @returns {null}
 */

HDPublicKey.prototype.xprivkey = function xprivkey() {
  return null;
};

/**
 * Get cached base58 xpubkey.
 * @returns {Base58String}
 */

HDPublicKey.prototype.xpubkey = function xpubkey() {
  if (!this._xpubkey)
    this._xpubkey = this.toBase58();
  return this._xpubkey;
};

/**
 * Destroy the key (zeroes chain code and pubkey).
 */

HDPublicKey.prototype.destroy = function destroy() {
  this.depth = 0;
  this.childIndex = 0;
  this.parentFingerPrint = 0;

  cleanse(this.chainCode);
  cleanse(this.publicKey);

  this.fingerPrint = -1;

  this._xpubkey = null;
};

/**
 * Derive a child key.
 * @param {Number} index - Derivation index.
 * @param {Boolean?} hardened - Whether the derivation
 * should be hardened (throws if true).
 * @returns {HDPrivateKey}
 * @throws on `hardened`
 */

HDPublicKey.prototype.derive = function derive(index, hardened) {
  assert(typeof index === 'number');

  if ((index >>> 0) !== index)
    throw new Error('Index out of range.');

  if ((index & common.HARDENED) || hardened)
    throw new Error('Cannot derive hardened.');

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

  const id = this.getID(index);
  const cache = common.cache.get(id);

  if (cache)
    return cache;

  const bw = StaticWriter.pool(37);

  bw.writeBytes(this.publicKey);
  bw.writeU32BE(index);

  const data = bw.render();

  const hash = digest.hmac('sha512', data, this.chainCode);
  const left = hash.slice(0, 32);
  const right = hash.slice(32, 64);

  let key;
  try {
    key = secp256k1.publicKeyTweakAdd(this.publicKey, left, true);
  } catch (e) {
    return this.derive(index + 1);
  }

  if (this.fingerPrint === -1) {
    const fp = digest.hash160(this.publicKey);
    this.fingerPrint = fp.readUInt32BE(0, true);
  }

  const child = new HDPublicKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = right;
  child.publicKey = key;

  common.cache.set(id, child);

  return child;
};

/**
 * Unique HD key ID.
 * @private
 * @param {Number} index
 * @returns {String}
 */

HDPublicKey.prototype.getID = function getID(index) {
  return this.network.keyPrefix.xpubkey58
    + this.publicKey.toString('hex')
    + index;
};

/**
 * Derive a BIP44 account key (does not derive, only ensures account key).
 * @method
 * @param {Number} purpose
 * @param {Number} account
 * @returns {HDPublicKey}
 * @throws Error if key is not already an account key.
 */

HDPublicKey.prototype.deriveAccount = function deriveAccount(purpose, account) {
  assert(util.isU32(purpose));
  assert(util.isU32(account));
  assert(this.isAccount(account), 'Cannot derive account index.');
  return this;
};

/**
 * Test whether the key is a master key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isMaster = function isMaster() {
  return common.isMaster(this);
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @method
 * @param {Number?} account
 * @returns {Boolean}
 */

HDPublicKey.prototype.isAccount = function isAccount(account) {
  return common.isAccount(this, account);
};

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPublicKey.isValidPath = function isValidPath(path) {
  try {
    common.parsePath(path, false);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Derive a key from a derivation path.
 * @param {String} path
 * @returns {HDPublicKey}
 * @throws Error if `path` is not a valid path.
 * @throws Error if hardened.
 */

HDPublicKey.prototype.derivePath = function derivePath(path) {
  const indexes = common.parsePath(path, false);

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

HDPublicKey.prototype.equals = function equals(obj) {
  assert(HDPublicKey.isHDPublicKey(obj));

  return this.network === obj.network
    && this.depth === obj.depth
    && this.parentFingerPrint === obj.parentFingerPrint
    && this.childIndex === obj.childIndex
    && this.chainCode.equals(obj.chainCode)
    && this.publicKey.equals(obj.publicKey);
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.prototype.compare = function compare(key) {
  assert(HDPublicKey.isHDPublicKey(key));

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

  cmp = this.publicKey.compare(key.publicKey);

  if (cmp !== 0)
    return cmp;

  return 0;
};

/**
 * Convert key to a more json-friendly object.
 * @returns {Object}
 */

HDPublicKey.prototype.toJSON = function toJSON() {
  return {
    xpubkey: this.xpubkey()
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @param {Network?} network
 */

HDPublicKey.prototype.fromJSON = function fromJSON(json, network) {
  assert(json.xpubkey, 'Could not handle HD key JSON.');
  this.fromBase58(json.xpubkey, network);
  return this;
};

/**
 * Instantiate an HDPublicKey from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @param {Network?} network
 * @returns {HDPrivateKey}
 */

HDPublicKey.fromJSON = function fromJSON(json, network) {
  return new HDPublicKey().fromJSON(json, network);
};

/**
 * Test whether an object is in the form of a base58 xpubkey.
 * @param {String} data
 * @param {(Network|NetworkType)?} network
 * @returns {Boolean}
 */

HDPublicKey.isBase58 = function isBase58(data, network) {
  if (typeof data !== 'string')
    return false;

  if (data.length < 4)
    return false;

  const prefix = data.substring(0, 4);

  try {
    Network.fromPublic58(prefix, network);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Test whether a buffer has a valid network prefix.
 * @param {Buffer} data
 * @param {(Network|NetworkType)?} network
 * @returns {NetworkType}
 */

HDPublicKey.isRaw = function isRaw(data, network) {
  if (!Buffer.isBuffer(data))
    return false;

  if (data.length < 4)
    return false;

  const version = data.readUInt32BE(0, true);

  try {
    Network.fromPublic(version, network);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Inject properties from a base58 key.
 * @private
 * @param {Base58String} xkey
 * @param {Network?} network
 */

HDPublicKey.prototype.fromBase58 = function fromBase58(xkey, network) {
  assert(typeof xkey === 'string');
  this._xpubkey = xkey;
  return this.fromRaw(base58.decode(xkey), network);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {BufferReader} br
 * @param {(Network|NetworkType)?} network
 */

HDPublicKey.prototype.fromReader = function fromReader(br, network) {
  const version = br.readU32BE();

  this.network = Network.fromPublic(version, network);
  this.depth = br.readU8();
  this.parentFingerPrint = br.readU32BE();
  this.childIndex = br.readU32BE();
  this.chainCode = br.readBytes(32);
  this.publicKey = br.readBytes(33);

  br.verifyChecksum();

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @param {(Network|NetworkType)?} network
 */

HDPublicKey.prototype.fromRaw = function fromRaw(data, network) {
  return this.fromReader(new BufferReader(data), network);
};

/**
 * Serialize key data to base58 extended key.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

HDPublicKey.prototype.toBase58 = function toBase58(network) {
  return base58.encode(this.toRaw(network));
};

/**
 * Write the key to a buffer writer.
 * @param {BufferWriter} bw
 * @param {(Network|NetworkType)?} network
 */

HDPublicKey.prototype.toWriter = function toWriter(bw, network) {
  if (!network)
    network = this.network;

  network = Network.get(network);

  bw.writeU32BE(network.keyPrefix.xpubkey);
  bw.writeU8(this.depth);
  bw.writeU32BE(this.parentFingerPrint);
  bw.writeU32BE(this.childIndex);
  bw.writeBytes(this.chainCode);
  bw.writeBytes(this.publicKey);
  bw.writeChecksum();

  return bw;
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

HDPublicKey.prototype.getSize = function getSize() {
  return 82;
};

/**
 * Serialize the key.
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPublicKey.prototype.toRaw = function toRaw(network) {
  return this.toWriter(new StaticWriter(82), network).render();
};

/**
 * Instantiate an HD public key from a base58 string.
 * @param {Base58String} xkey
 * @param {Network?} network
 * @returns {HDPublicKey}
 */

HDPublicKey.fromBase58 = function fromBase58(xkey, network) {
  return new HDPublicKey().fromBase58(xkey, network);
};

/**
 * Instantiate key from serialized data.
 * @param {BufferReader} br
 * @param {(Network|NetworkType)?} network
 * @returns {HDPublicKey}
 */

HDPublicKey.fromReader = function fromReader(br, network) {
  return new HDPublicKey().fromReader(br, network);
};

/**
 * Instantiate key from serialized data.
 * @param {Buffer} data
 * @param {(Network|NetworkType)?} network
 * @returns {HDPublicKey}
 */

HDPublicKey.fromRaw = function fromRaw(data, network) {
  return new HDPublicKey().fromRaw(data, network);
};

/**
 * Test whether an object is a HDPublicKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.isHDPublicKey = function isHDPublicKey(obj) {
  return obj instanceof HDPublicKey;
};

/*
 * Expose
 */

module.exports = HDPublicKey;
