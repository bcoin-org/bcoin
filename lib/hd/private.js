/*!
 * private.js - hd private keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var ec = require('../crypto/ec');
var assert = require('assert');
var constants = require('../protocol/constants');
var networks = require('../protocol/networks');
var Network = require('../protocol/network');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var base58 = require('../utils/base58');
var Mnemonic = require('./mnemonic');
var HDPublicKey = require('./public');
var common = require('./common');

/*
 * Constants
 */

var FINGER_PRINT = new Buffer('00000000', 'hex');
var SEED_SALT = new Buffer('Bitcoin seed', 'ascii');

/**
 * HDPrivateKey
 * @exports HDPrivateKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Mnemonic?} options.mnemonic
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.privateKey
 * @property {Network} network
 * @property {Base58String} xprivkey
 * @property {Base58String} xpubkey
 * @property {Mnemonic?} mnemonic
 * @property {Number} depth
 * @property {Buffer} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} privateKey
 * @property {HDPublicKey} hdPublicKey
 */

function HDPrivateKey(options) {
  if (!(this instanceof HDPrivateKey))
    return new HDPrivateKey(options);

  this.network = Network.primary;
  this.depth = 0;
  this.parentFingerPrint = FINGER_PRINT;
  this.childIndex = 0;
  this.chainCode = constants.ZERO_HASH;
  this.privateKey = constants.ZERO_HASH;

  this.publicKey = constants.ZERO_KEY;
  this.fingerPrint = null;

  this.mnemonic = null;

  this._xprivkey = null;

  this.hdPrivateKey = this;
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
  assert(util.isNumber(options.depth));
  assert(Buffer.isBuffer(options.parentFingerPrint));
  assert(util.isNumber(options.childIndex));
  assert(Buffer.isBuffer(options.chainCode));
  assert(Buffer.isBuffer(options.privateKey));
  assert(options.depth <= 0xff, 'Depth is too high.');

  if (options.network)
    this.network = Network.get(options.network);

  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.privateKey = options.privateKey;
  this.publicKey = ec.publicKeyCreate(options.privateKey, true);

  if (options.mnemonic) {
    assert(options.mnemonic instanceof Mnemonic);
    this.mnemonic = options.mnemonic;
  }

  if (options.xprivkey) {
    assert(typeof options.xprivkey === 'string');
    this._xprivkey = options.xprivkey;
  }

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

HDPrivateKey.prototype.__defineGetter__('hdPublicKey', function() {
  var key = this._hdPublicKey;

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
});

HDPrivateKey.prototype.__defineGetter__('xprivkey', function() {
  if (!this._xprivkey)
    this._xprivkey = this.toBase58();
  return this._xprivkey;
});

HDPrivateKey.prototype.__defineGetter__('xpubkey', function() {
  return this.hdPublicKey.xpubkey;
});

/**
 * Destroy the key (zeroes chain code, privkey, and pubkey).
 * @param {Boolean} pub - Destroy hd public key as well.
 */

HDPrivateKey.prototype.destroy = function destroy(pub) {
  this.depth = 0;
  this.childIndex = 0;

  crypto.cleanse(this.parentFingerPrint);
  crypto.cleanse(this.chainCode);
  crypto.cleanse(this.privateKey);
  crypto.cleanse(this.publicKey);

  if (this.fingerPrint) {
    crypto.cleanse(this.fingerPrint);
    this.fingerPrint = null;
  }

  if (this._hdPublicKey) {
    if (pub)
      this._hdPublicKey.destroy();
    this._hdPublicKey = null;
  }

  this._xprivkey = null;

  if (this.mnemonic) {
    this.mnemonic.destroy();
    this.mnemonic = null;
  }
};

/**
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation should be hardened.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derive = function derive(index, hardened, cache) {
  var bw, id, data, hash, left, right, key, child;

  if (typeof hardened !== 'boolean') {
    cache = hardened;
    hardened = false;
  }

  if (!cache)
    cache = common.cache;

  if (typeof index === 'string')
    return this.derivePath(index, cache);

  hardened = index >= constants.hd.HARDENED ? true : hardened;

  if (index < constants.hd.HARDENED && hardened)
    index += constants.hd.HARDENED;

  if (!(index >= 0 && index < constants.hd.MAX_INDEX))
    throw new Error('Index out of range.');

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

  if (cache) {
    id = this.getID(index);
    child = cache.get(id);
    if (child)
      return child;
  }

  bw = new BufferWriter();

  if (hardened) {
    bw.writeU8(0);
    bw.writeBytes(this.privateKey);
    bw.writeU32BE(index);
  } else {
    bw.writeBytes(this.publicKey);
    bw.writeU32BE(index);
  }

  data = bw.render();

  hash = crypto.hmac('sha512', data, this.chainCode);
  left = hash.slice(0, 32);
  right = hash.slice(32, 64);

  try {
    key = ec.privateKeyTweakAdd(this.privateKey, left);
  } catch (e) {
    return this.derive(index + 1, cache);
  }

  if (!this.fingerPrint)
    this.fingerPrint = crypto.hash160(this.publicKey).slice(0, 4);

  child = new HDPrivateKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = right;
  child.privateKey = key;
  child.publicKey = ec.publicKeyCreate(key, true);

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

HDPrivateKey.prototype.getID = function getID(index) {
  return this.network.keyPrefix.xprivkey58
    + this.publicKey.toString('hex')
    + index;
};

/**
 * Derive a BIP44 account key.
 * @param {Number} accountIndex
 * @returns {HDPrivateKey}
 * @throws Error if key is not a master key.
 */

HDPrivateKey.prototype.deriveAccount44 = function deriveAccount44(accountIndex, cache) {
  assert(util.isNumber(accountIndex), 'Account index must be a number.');
  assert(this.isMaster(), 'Cannot derive account index.');
  return this
    .derive(44, true, cache)
    .derive(this.network.keyPrefix.coinType, true, cache)
    .derive(accountIndex, true, cache);
};

/**
 * Derive a BIP45 purpose key.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45(cache) {
  assert(this.isMaster(), 'Cannot derive purpose 45.');
  return this.derive(45, true, cache);
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
 * @param {Number?} accountIndex
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isAccount44 = function isAccount44(accountIndex) {
  return common.isAccount44(this, accountIndex);
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isPurpose45 = function isPurpose45() {
  return common.isPurpose45(this);
};

/**
 * Test whether an object is in the form of a base58 xprivkey.
 * @param {String} data
 * @returns {Boolean}
 */

HDPrivateKey.isBase58 = function isBase58(data) {
  var i, type, prefix;

  if (typeof data !== 'string')
    return false;

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xprivkey58;
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

HDPrivateKey.isRaw = function isRaw(data) {
  var i, version, prefix, type;

  if (!Buffer.isBuffer(data))
    return false;

  if (data.length < 4)
    return false;

  version = data.readUInt32BE(0, true);

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xprivkey;
    if (version === prefix)
      return type;
  }

  return false;
};

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPrivateKey.isValidPath = function isValidPath(path) {
  if (typeof path !== 'string')
    return false;

  try {
    common.parsePath(path, constants.hd.MAX_INDEX);
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

HDPrivateKey.prototype.derivePath = function derivePath(path, cache) {
  var indexes = common.parsePath(path, constants.hd.MAX_INDEX);
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

HDPrivateKey.prototype.equal = function equal(obj) {
  if (!HDPrivateKey.isHDPrivateKey(obj))
    return false;

  return this.network === obj.network
    && this.depth === obj.depth
    && util.equal(this.parentFingerPrint, obj.parentFingerPrint)
    && this.childIndex === obj.childIndex
    && util.equal(this.chainCode, obj.chainCode)
    && util.equal(this.privateKey, obj.privateKey);
};

/**
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.prototype.compare = function compare(key) {
  var cmp;

  if (!HDPrivateKey.isHDPrivateKey(key))
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

  cmp = util.cmp(this.privateKey, key.privateKey);

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
  var hash, left, right;

  assert(Buffer.isBuffer(seed));

  if (!(seed.length * 8 >= constants.hd.MIN_ENTROPY
      && seed.length * 8 <= constants.hd.MAX_ENTROPY)) {
    throw new Error('Entropy not in range.');
  }

  hash = crypto.hmac('sha512', seed, SEED_SALT);

  left = hash.slice(0, 32);
  right = hash.slice(32, 64);

  // Only a 1 in 2^127 chance of happening.
  if (!ec.privateKeyVerify(left))
    throw new Error('Master private key is invalid.');

  this.network = Network.get(network);
  this.depth = 0;
  this.parentFingerPrint = new Buffer([0, 0, 0, 0]);
  this.childIndex = 0;
  this.chainCode = right;
  this.privateKey = left;
  this.publicKey = ec.publicKeyCreate(left, true);

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
 * @param {Mnemonic|Object} mnemonic
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromMnemonic = function fromMnemonic(mnemonic, network) {
  if (!(mnemonic instanceof Mnemonic))
    mnemonic = new Mnemonic(mnemonic);
  this.fromSeed(mnemonic.toSeed(), network);
  this.mnemonic = mnemonic;
  return this;
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic|Object} mnemonic
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromMnemonic = function fromMnemonic(mnemonic, network) {
  return new HDPrivateKey().fromMnemonic(mnemonic, network);
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
  this.parentFingerPrint = new Buffer([0, 0, 0, 0]);
  this.childIndex = 0;
  this.chainCode = entropy;
  this.privateKey = key;
  this.publicKey = ec.publicKeyCreate(key, true);
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
  var key = ec.generatePrivateKey();
  var entropy = crypto.randomBytes(32);
  return HDPrivateKey.fromKey(key, entropy, network);
};

/**
 * Inject properties from base58 key.
 * @private
 * @param {Base58String} xkey
 */

HDPrivateKey.prototype.fromBase58 = function fromBase58(xkey) {
  this.fromRaw(base58.decode(xkey));
  this._xprivkey = xkey;
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

HDPrivateKey.prototype.fromRaw = function fromRaw(raw) {
  var br = new BufferReader(raw);
  var i, version, type, prefix;

  version = br.readU32BE();
  this.depth = br.readU8();
  this.parentFingerPrint = br.readBytes(4);
  this.childIndex = br.readU32BE();
  this.chainCode = br.readBytes(32);
  br.readU8();
  this.privateKey = br.readBytes(32);
  br.verifyChecksum();

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xprivkey;
    if (version === prefix)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

  this.publicKey = ec.publicKeyCreate(this.privateKey, true);
  this.network = Network.get(type);

  return this;
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
 * Serialize the key.
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPrivateKey.prototype.toRaw = function toRaw(network, writer) {
  var bw = new BufferWriter(writer);

  if (!network)
    network = this.network;

  network = Network.get(network);

  bw.writeU32BE(network.keyPrefix.xprivkey);
  bw.writeU8(this.depth);
  bw.writeBytes(this.parentFingerPrint);
  bw.writeU32BE(this.childIndex);
  bw.writeBytes(this.chainCode);
  bw.writeU8(0);
  bw.writeBytes(this.privateKey);
  bw.writeChecksum();

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Serialize the key in "extended"
 * format (includes the mnemonic).
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPrivateKey.prototype.toExtended = function toExtended(network, writer) {
  var bw = new BufferWriter(writer);

  this.toRaw(network, bw);

  if (this.mnemonic) {
    bw.writeU8(1);
    this.mnemonic.toRaw(bw);
  } else {
    bw.writeU8(0);
  }

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from extended serialized data.
 * @private
 * @param {Buffer} data
 */

HDPrivateKey.prototype.fromExtended = function fromExtended(data) {
  var br = new BufferReader(data);
  this.fromRaw(br);
  if (br.readU8() === 1)
    this.mnemonic = Mnemonic.fromRaw(br);
  return this;
};

/**
 * Instantiate key from "extended" serialized data.
 * @param {Buffer} data
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromExtended = function fromExtended(data) {
  return new HDPrivateKey().fromExtended(data);
};

/**
 * Instantiate an HD private key from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromBase58 = function fromBase58(xkey) {
  return new HDPrivateKey().fromBase58(xkey);
};

/**
 * Instantiate key from serialized data.
 * @param {Buffer} raw
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromRaw = function fromRaw(raw) {
  return new HDPrivateKey().fromRaw(raw);
};

/**
 * Convert key to a more json-friendly object.
 * @returns {Object}
 */

HDPrivateKey.prototype.toJSON = function toJSON() {
  return {
    xprivkey: this.xprivkey,
    mnemonic: this.mnemonic ? this.mnemonic.toJSON() : null
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

HDPrivateKey.prototype.fromJSON = function fromJSON(json) {
  assert(json.xprivkey, 'Could not handle key JSON.');

  this.fromBase58(json.xprivkey);

  if (json.mnemonic)
    this.mnemonic = Mnemonic.fromJSON(json.mnemonic);

  return this;
};

/**
 * Instantiate an HDPrivateKey from a jsonified key object.
 * @param {Object} json - The jsonified key object.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromJSON = function fromJSON(json) {
  return new HDPrivateKey().fromJSON(json);
};

/**
 * Test whether an object is an HDPrivateKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.isHDPrivateKey = function isHDPrivateKey(obj) {
  return obj
    && typeof obj.derive === 'function'
    && typeof obj.toExtended === 'function'
    && obj.chainCode !== undefined;
};

/*
 * Expose
 */

module.exports = HDPrivateKey;
