/*!
 * public.js - hd public keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const {base58} = require('bstring');
const sha512 = require('bcrypto/lib/sha512');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const cleanse = require('bcrypto/lib/cleanse');
const secp256k1 = require('bcrypto/lib/secp256k1');
const Network = require('../protocol/network');
const consensus = require('../protocol/consensus');
const common = require('./common');

/**
 * HDPublicKey
 * @alias module:hd.PublicKey
 * @property {Number} depth
 * @property {Number} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} publicKey
 */

class HDPublicKey {
  /**
   * Create an HD public key.
   * @constructor
   * @param {Object|Base58String} options
   * @param {Base58String?} options.xkey - Serialized base58 key.
   * @param {Number?} options.depth
   * @param {Number?} options.parentFingerPrint
   * @param {Number?} options.childIndex
   * @param {Buffer?} options.chainCode
   * @param {Buffer?} options.publicKey
   */

  constructor(options) {
    this.depth = 0;
    this.parentFingerPrint = 0;
    this.childIndex = 0;
    this.chainCode = consensus.ZERO_HASH;
    this.publicKey = common.ZERO_KEY;

    this.fingerPrint = -1;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'No options for HDPublicKey');
    assert((options.depth & 0xff) === options.depth);
    assert((options.parentFingerPrint >>> 0) === options.parentFingerPrint);
    assert((options.childIndex >>> 0) === options.childIndex);
    assert(Buffer.isBuffer(options.chainCode));
    assert(Buffer.isBuffer(options.publicKey));

    this.depth = options.depth;
    this.parentFingerPrint = options.parentFingerPrint;
    this.childIndex = options.childIndex;
    this.chainCode = options.chainCode;
    this.publicKey = options.publicKey;

    return this;
  }

  /**
   * Instantiate HD public key from options object.
   * @param {Object} options
   * @returns {HDPublicKey}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Get HD public key (self).
   * @returns {HDPublicKey}
   */

  toPublic() {
    return this;
  }

  /**
   * Get cached base58 xprivkey (always null here).
   * @returns {null}
   */

  xprivkey(network) {
    return null;
  }

  /**
   * Get cached base58 xpubkey.
   * @returns {Base58String}
   */

  xpubkey(network) {
    return this.toBase58(network);
  }

  /**
   * Destroy the key (zeroes chain code and pubkey).
   */

  destroy() {
    this.depth = 0;
    this.childIndex = 0;
    this.parentFingerPrint = 0;

    cleanse(this.chainCode);
    cleanse(this.publicKey);

    this.fingerPrint = -1;
  }

  /**
   * Derive a child key.
   * @param {Number} index - Derivation index.
   * @param {Boolean?} hardened - Whether the derivation
   * should be hardened (throws if true).
   * @returns {HDPrivateKey}
   * @throws on `hardened`
   */

  derive(index, hardened) {
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

    const bw = bio.pool(37);

    bw.writeBytes(this.publicKey);
    bw.writeU32BE(index);

    const data = bw.render();

    const hash = sha512.mac(data, this.chainCode);
    const left = hash.slice(0, 32);
    const right = hash.slice(32, 64);

    let key;
    try {
      key = secp256k1.publicKeyTweakAdd(this.publicKey, left, true);
    } catch (e) {
      return this.derive(index + 1);
    }

    if (this.fingerPrint === -1) {
      const fp = hash160.digest(this.publicKey);
      this.fingerPrint = fp.readUInt32BE(0, true);
    }

    const child = new this.constructor();
    child.depth = this.depth + 1;
    child.parentFingerPrint = this.fingerPrint;
    child.childIndex = index;
    child.chainCode = right;
    child.publicKey = key;

    common.cache.set(id, child);

    return child;
  }

  /**
   * Unique HD key ID.
   * @private
   * @param {Number} index
   * @returns {String}
   */

  getID(index) {
    return 'b' + this.publicKey.toString('hex') + index;
  }

  /**
   * Derive a BIP44 account key (does not derive, only ensures account key).
   * @method
   * @param {Number} purpose
   * @param {Number} type
   * @param {Number} account
   * @returns {HDPublicKey}
   * @throws Error if key is not already an account key.
   */

  deriveAccount(purpose, type, account) {
    assert((purpose >>> 0) === purpose);
    assert((type >>> 0) === type);
    assert((account >>> 0) === account);
    assert(this.isAccount(account), 'Cannot derive account index.');
    return this;
  }

  /**
   * Test whether the key is a master key.
   * @method
   * @returns {Boolean}
   */

  isMaster() {
    return common.isMaster(this);
  }

  /**
   * Test whether the key is (most likely) a BIP44 account key.
   * @method
   * @param {Number?} account
   * @returns {Boolean}
   */

  isAccount(account) {
    return common.isAccount(this, account);
  }

  /**
   * Test whether a string is a valid path.
   * @param {String} path
   * @param {Boolean?} hardened
   * @returns {Boolean}
   */

  static isValidPath(path) {
    try {
      common.parsePath(path, false);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Derive a key from a derivation path.
   * @param {String} path
   * @returns {HDPublicKey}
   * @throws Error if `path` is not a valid path.
   * @throws Error if hardened.
   */

  derivePath(path) {
    const indexes = common.parsePath(path, false);

    let key = this;

    for (const index of indexes)
      key = key.derive(index);

    return key;
  }

  /**
   * Compare a key against an object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  equals(obj) {
    assert(HDPublicKey.isHDPublicKey(obj));

    return this.depth === obj.depth
      && this.parentFingerPrint === obj.parentFingerPrint
      && this.childIndex === obj.childIndex
      && this.chainCode.equals(obj.chainCode)
      && this.publicKey.equals(obj.publicKey);
  }

  /**
   * Compare a key against an object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  compare(key) {
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
  }

  /**
   * Convert key to a more json-friendly object.
   * @returns {Object}
   */

  toJSON(network) {
    return {
      xpubkey: this.xpubkey(network)
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @param {Network?} network
   */

  fromJSON(json, network) {
    assert(json.xpubkey, 'Could not handle HD key JSON.');
    this.fromBase58(json.xpubkey, network);
    return this;
  }

  /**
   * Instantiate an HDPublicKey from a jsonified key object.
   * @param {Object} json - The jsonified transaction object.
   * @param {Network?} network
   * @returns {HDPrivateKey}
   */

  static fromJSON(json, network) {
    return new this().fromJSON(json, network);
  }

  /**
   * Test whether an object is in the form of a base58 xpubkey.
   * @param {String} data
   * @param {(Network|NetworkType)?} network
   * @returns {Boolean}
   */

  static isBase58(data, network) {
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
  }

  /**
   * Test whether a buffer has a valid network prefix.
   * @param {Buffer} data
   * @param {(Network|NetworkType)?} network
   * @returns {NetworkType}
   */

  static isRaw(data, network) {
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
  }

  /**
   * Inject properties from a base58 key.
   * @private
   * @param {Base58String} xkey
   * @param {Network?} network
   */

  fromBase58(xkey, network) {
    assert(typeof xkey === 'string');
    return this.fromRaw(base58.decode(xkey), network);
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} br
   * @param {(Network|NetworkType)?} network
   */

  fromReader(br, network) {
    const version = br.readU32BE();

    Network.fromPublic(version, network);

    this.depth = br.readU8();
    this.parentFingerPrint = br.readU32BE();
    this.childIndex = br.readU32BE();
    this.chainCode = br.readBytes(32);
    this.publicKey = br.readBytes(33);

    br.verifyChecksum(hash256.digest);

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @param {(Network|NetworkType)?} network
   */

  fromRaw(data, network) {
    return this.fromReader(bio.read(data), network);
  }

  /**
   * Serialize key data to base58 extended key.
   * @param {(Network|NetworkType)?} network
   * @returns {Base58String}
   */

  toBase58(network) {
    return base58.encode(this.toRaw(network));
  }

  /**
   * Write the key to a buffer writer.
   * @param {BufferWriter} bw
   * @param {(Network|NetworkType)?} network
   */

  toWriter(bw, network) {
    network = Network.get(network);

    bw.writeU32BE(network.keyPrefix.xpubkey);
    bw.writeU8(this.depth);
    bw.writeU32BE(this.parentFingerPrint);
    bw.writeU32BE(this.childIndex);
    bw.writeBytes(this.chainCode);
    bw.writeBytes(this.publicKey);
    bw.writeChecksum(hash256.digest);

    return bw;
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    return 82;
  }

  /**
   * Serialize the key.
   * @param {(Network|NetworkType)?} network
   * @returns {Buffer}
   */

  toRaw(network) {
    return this.toWriter(bio.write(82), network).render();
  }

  /**
   * Instantiate an HD public key from a base58 string.
   * @param {Base58String} xkey
   * @param {Network?} network
   * @returns {HDPublicKey}
   */

  static fromBase58(xkey, network) {
    return new this().fromBase58(xkey, network);
  }

  /**
   * Instantiate key from serialized data.
   * @param {BufferReader} br
   * @param {(Network|NetworkType)?} network
   * @returns {HDPublicKey}
   */

  static fromReader(br, network) {
    return new this().fromReader(br, network);
  }

  /**
   * Instantiate key from serialized data.
   * @param {Buffer} data
   * @param {(Network|NetworkType)?} network
   * @returns {HDPublicKey}
   */

  static fromRaw(data, network) {
    return new this().fromRaw(data, network);
  }

  /**
   * Test whether an object is a HDPublicKey.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isHDPublicKey(obj) {
    return obj instanceof HDPublicKey;
  }
}

/*
 * Expose
 */

module.exports = HDPublicKey;
