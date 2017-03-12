/*!
 * public.js - hd public keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var ec = require('../crypto/ec');
var networks = require('../protocol/networks');
var Network = require('../protocol/network');
var StaticWriter = require('../utils/staticwriter');
var BufferReader = require('../utils/reader');
var base58 = require('../utils/base58');
var encoding = require('../utils/encoding');
var common = require('./common');

/**
 * HDPublicKey
 * @alias module:hd.PublicKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.publicKey
 * @property {Network} network
 * @property {Number} depth
 * @property {Buffer} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} publicKey
 */

function HDPublicKey(options) {
  if (!(this instanceof HDPublicKey))
    return new HDPublicKey(options);

  this.network = Network.primary;
  this.depth = 0;
  this.parentFingerPrint = encoding.ZERO_U32;
  this.childIndex = 0;
  this.chainCode = encoding.ZERO_HASH;
  this.publicKey = encoding.ZERO_KEY;

  this.fingerPrint = null;

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
  assert(util.isNumber(options.depth));
  assert(Buffer.isBuffer(options.parentFingerPrint));
  assert(util.isNumber(options.childIndex));
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

HDPublicKey.prototype.xpubkey = function() {
  if (!this._xpubkey)
    this._xpubkey = this.toBase58();
  return this._xpubkey;
};

/**
 * Verify network.
 * @param {(NetworkType|Network)} network
 * @returns {Boolean}
 */

HDPublicKey.prototype.verifyNetwork = function verifyNetwork(network) {
  network = Network.get(network);
  return this.network.keyPrefix.xpubkey === network.keyPrefix.xpubkey
    && this.network.keyPrefix.coinType === network.keyPrefix.coinType;
};

/**
 * Destroy the key (zeroes chain code and pubkey).
 */

HDPublicKey.prototype.destroy = function destroy() {
  this.depth = 0;
  this.childIndex = 0;

  crypto.cleanse(this.parentFingerPrint);
  crypto.cleanse(this.chainCode);
  crypto.cleanse(this.publicKey);

  if (this.fingerPrint) {
    crypto.cleanse(this.fingerPrint);
    this.fingerPrint = null;
  }

  this._xpubkey = null;
};

/**
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation
 * should be hardened (throws if true).
 * @returns {HDPrivateKey}
 * @throws on `hardened`
 */

HDPublicKey.prototype.derive = function derive(index, hardened, cache) {
  var bw, id, data, hash, left, right, key, child;

  if (typeof hardened !== 'boolean') {
    cache = hardened;
    hardened = false;
  }

  if (!cache)
    cache = common.cache;

  if (typeof index === 'string')
    return this.derivePath(index, cache);

  if (index >= common.HARDENED || hardened)
    throw new Error('Index out of range.');

  if (index < 0)
    throw new Error('Index out of range.');

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

  if (cache) {
    id = this.getID(index);
    child = cache.get(id);
    if (child)
      return child;
  }

  bw = new StaticWriter(37);
  bw.writeBytes(this.publicKey);
  bw.writeU32BE(index);
  data = bw.render();

  hash = crypto.hmac('sha512', data, this.chainCode);
  left = hash.slice(0, 32);
  right = hash.slice(32, 64);

  try {
    key = ec.publicKeyTweakAdd(this.publicKey, left, true);
  } catch (e) {
    return this.derive(index + 1, cache);
  }

  if (!this.fingerPrint)
    this.fingerPrint = crypto.hash160(this.publicKey).slice(0, 4);

  child = new HDPublicKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = right;
  child.publicKey = key;

  if (cache)
    cache.set(id, child);

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
 * @param {Number} accountIndex
 * @returns {HDPublicKey}
 * @throws Error if key is not already an account key.
 */

HDPublicKey.prototype.deriveAccount44 = function deriveAccount44(accountIndex) {
  assert(this.isAccount44(accountIndex), 'Cannot derive account index.');
  return this;
};

/**
 * Derive a BIP45 purpose key (does not derive, only ensures account key).
 * @method
 * @returns {HDPublicKey}
 * @throws Error if key is not already a purpose key.
 */

HDPublicKey.prototype.derivePurpose45 = function derivePurpose45() {
  assert(this.isPurpose45(), 'Cannot derive purpose 45.');
  return this;
};

/**
 * Test whether the key is a master key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isMaster = function() {
  return common.isMaster(this);
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @method
 * @param {Number?} accountIndex
 * @returns {Boolean}
 */

HDPublicKey.prototype.isAccount44 = function(accountIndex) {
  return common.isAccount44(this, accountIndex);
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isPurpose45 = function() {
  return common.isPurpose45(this);
};

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPublicKey.isValidPath = function isValidPath(path) {
  if (typeof path !== 'string')
    return false;

  try {
    common.parsePath(path, common.HARDENED);
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

HDPublicKey.prototype.derivePath = function derivePath(path, cache) {
  var indexes = common.parsePath(path, common.HARDENED);
  var key = this;
  var i;

  for (i = 0; i < indexes.length; i++)
    key = key.derive(indexes[i], cache);

  return key;
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.prototype.equal = function equal(obj) {
  if (!HDPublicKey.isHDPublicKey(obj))
    return false;

  return this.network === obj.network
    && this.depth === obj.depth
    && util.equal(this.parentFingerPrint, obj.parentFingerPrint)
    && this.childIndex === obj.childIndex
    && util.equal(this.chainCode, obj.chainCode)
    && util.equal(this.publicKey, obj.publicKey);
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.prototype.compare = function compare(key) {
  var cmp;

  if (!HDPublicKey.isHDPublicKey(key))
    return 1;

  cmp = this.depth - key.depth;

  if (cmp !== 0)
    return cmp;

  cmp = util.cmp(this.parentFingerPrint, key.parentFingerPrint);

  if (cmp !== 0)
    return cmp;

  cmp = this.childIndex - key.childIndex;

  if (cmp !== 0)
    return cmp;

  cmp = util.cmp(this.chainCode, key.chainCode);

  if (cmp !== 0)
    return cmp;

  cmp = util.cmp(this.publicKey, key.publicKey);

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
 * @returns {Boolean}
 */

HDPublicKey.isBase58 = function isBase58(data) {
  var i, type, prefix;

  if (typeof data !== 'string')
    return false;

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xpubkey58;
    if (data.indexOf(prefix) === 0)
      return true;
  }

  return false;
};

/**
 * Test whether a buffer has a valid network prefix.
 * @param {Buffer} data
 * @returns {NetworkType}
 */

HDPublicKey.isRaw = function isRaw(data) {
  var i, version, prefix, type;

  if (!Buffer.isBuffer(data))
    return false;

  version = data.readUInt32BE(0, true);

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xpubkey;
    if (version === prefix)
      return type;
  }

  return false;
};

/**
 * Inject properties from a base58 key.
 * @private
 * @param {Base58String} xkey
 * @param {Network?} network
 */

HDPublicKey.prototype.fromBase58 = function fromBase58(xkey, network) {
  this.fromRaw(base58.decode(xkey));
  this._xpubkey = xkey;
  if (network && !this.verifyNetwork(network))
    throw new Error('Network mismatch for HD public key.');
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

HDPublicKey.prototype.fromReader = function fromReader(br) {
  var i, version, type, prefix;

  version = br.readU32BE();
  this.depth = br.readU8();
  this.parentFingerPrint = br.readBytes(4);
  this.childIndex = br.readU32BE();
  this.chainCode = br.readBytes(32);
  this.publicKey = br.readBytes(33);
  br.verifyChecksum();

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xpubkey;
    if (version === prefix)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

  this.network = Network.get(type);

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

HDPublicKey.prototype.fromRaw = function fromRaw(raw) {
  return this.fromReader(new BufferReader(raw));
};

/**
 * Serialize key data to base58 extended key.
 * @param {Network|String} network
 * @returns {Base58String}
 */

HDPublicKey.prototype.toBase58 = function toBase58(network) {
  return base58.encode(this.toRaw(network));
};

/**
 * Write the key to a buffer writer.
 * @param {BufferWriter} bw
 * @param {Network|NetworkType} network
 */

HDPublicKey.prototype.toWriter = function toWriter(bw, network) {
  if (!network)
    network = this.network;

  network = Network.get(network);

  bw.writeU32BE(network.keyPrefix.xpubkey);
  bw.writeU8(this.depth);
  bw.writeBytes(this.parentFingerPrint);
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
 * @param {Network|NetworkType} network
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
 * @returns {HDPublicKey}
 */

HDPublicKey.fromReader = function fromReader(br) {
  return new HDPublicKey().fromReader(br);
};

/**
 * Instantiate key from serialized data.
 * @param {Buffer} raw
 * @returns {HDPublicKey}
 */

HDPublicKey.fromRaw = function fromRaw(data) {
  return new HDPublicKey().fromRaw(data);
};

/**
 * Test whether an object is a HDPublicKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.isHDPublicKey = function isHDPublicKey(obj) {
  return obj
    && typeof obj.derive === 'function'
    && typeof obj.toExtended !== 'function'
    && obj.chainCode !== undefined;
};

/*
 * Expose
 */

module.exports = HDPublicKey;
