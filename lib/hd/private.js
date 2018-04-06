/*!
 * private.js - hd private keys for bcoin
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
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const Network = require('../protocol/network');
const consensus = require('../protocol/consensus');
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
 * @property {Number} depth
 * @property {Number} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} privateKey
 */

class HDPrivateKey {
  /**
   * Create an hd private key.
   * @constructor
   * @param {Object|String} options
   * @param {Number?} options.depth
   * @param {Number?} options.parentFingerPrint
   * @param {Number?} options.childIndex
   * @param {Buffer?} options.chainCode
   * @param {Buffer?} options.privateKey
   */

  constructor(options) {
    this.depth = 0;
    this.parentFingerPrint = 0;
    this.childIndex = 0;
    this.chainCode = consensus.ZERO_HASH;
    this.privateKey = consensus.ZERO_HASH;

    this.publicKey = common.ZERO_KEY;
    this.fingerPrint = -1;

    this._hdPublicKey = null;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'No options for HD private key.');
    assert((options.depth & 0xff) === options.depth);
    assert((options.parentFingerPrint >>> 0) === options.parentFingerPrint);
    assert((options.childIndex >>> 0) === options.childIndex);
    assert(Buffer.isBuffer(options.chainCode));
    assert(Buffer.isBuffer(options.privateKey));

    this.depth = options.depth;
    this.parentFingerPrint = options.parentFingerPrint;
    this.childIndex = options.childIndex;
    this.chainCode = options.chainCode;
    this.privateKey = options.privateKey;
    this.publicKey = secp256k1.publicKeyCreate(options.privateKey, true);

    return this;
  }

  /**
   * Instantiate HD private key from options object.
   * @param {Object} options
   * @returns {HDPrivateKey}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Get HD public key.
   * @returns {HDPublicKey}
   */

  toPublic() {
    let key = this._hdPublicKey;

    if (!key) {
      key = new HDPublicKey();
      key.depth = this.depth;
      key.parentFingerPrint = this.parentFingerPrint;
      key.childIndex = this.childIndex;
      key.chainCode = this.chainCode;
      key.publicKey = this.publicKey;
      this._hdPublicKey = key;
    }

    return key;
  }

  /**
   * Get cached base58 xprivkey.
   * @returns {Base58String}
   */

  xprivkey(network) {
    return this.toBase58(network);
  }

  /**
   * Get cached base58 xpubkey.
   * @returns {Base58String}
   */

  xpubkey(network) {
    return this.toPublic().xpubkey(network);
  }

  /**
   * Destroy the key (zeroes chain code, privkey, and pubkey).
   * @param {Boolean} pub - Destroy hd public key as well.
   */

  destroy(pub) {
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
  }

  /**
   * Derive a child key.
   * @param {Number} index - Derivation index.
   * @param {Boolean?} hardened - Whether the derivation should be hardened.
   * @returns {HDPrivateKey}
   */

  derive(index, hardened) {
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

    const bw = bio.pool(37);

    if (index & common.HARDENED) {
      bw.writeU8(0);
      bw.writeBytes(this.privateKey);
      bw.writeU32BE(index);
    } else {
      bw.writeBytes(this.publicKey);
      bw.writeU32BE(index);
    }

    const data = bw.render();

    const hash = sha512.mac(data, this.chainCode);
    const left = hash.slice(0, 32);
    const right = hash.slice(32, 64);

    let key;
    try {
      key = secp256k1.privateKeyTweakAdd(this.privateKey, left);
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
    child.privateKey = key;
    child.publicKey = secp256k1.publicKeyCreate(key, true);

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
    return 'v' + this.publicKey.toString('hex') + index;
  }

  /**
   * Derive a BIP44 account key.
   * @param {Number} purpose
   * @param {Number} type
   * @param {Number} account
   * @returns {HDPrivateKey}
   * @throws Error if key is not a master key.
   */

  deriveAccount(purpose, type, account) {
    assert((purpose >>> 0) === purpose, 'Purpose must be a number.');
    assert((type >>> 0) === type, 'Account index must be a number.');
    assert((account >>> 0) === account, 'Account index must be a number.');
    assert(this.isMaster(), 'Cannot derive account index.');
    return this
      .derive(purpose, true)
      .derive(type, true)
      .derive(account, true);
  }

  /**
   * Test whether the key is a master key.
   * @returns {Boolean}
   */

  isMaster() {
    return common.isMaster(this);
  }

  /**
   * Test whether the key is (most likely) a BIP44 account key.
   * @param {Number?} account
   * @returns {Boolean}
   */

  isAccount(account) {
    return common.isAccount(this, account);
  }

  /**
   * Test whether an object is in the form of a base58 xprivkey.
   * @param {String} data
   * @param {Network?} network
   * @returns {Boolean}
   */

  static isBase58(data, network) {
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
  }

  /**
   * Test whether a buffer has a valid network prefix.
   * @param {Buffer} data
   * @param {Network?} network
   * @returns {Boolean}
   */

  static isRaw(data, network) {
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
  }

  /**
   * Test whether a string is a valid path.
   * @param {String} path
   * @returns {Boolean}
   */

  static isValidPath(path) {
    try {
      common.parsePath(path, true);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Derive a key from a derivation path.
   * @param {String} path
   * @returns {HDPrivateKey}
   * @throws Error if `path` is not a valid path.
   */

  derivePath(path) {
    const indexes = common.parsePath(path, true);

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
    assert(HDPrivateKey.isHDPrivateKey(obj));

    return this.depth === obj.depth
      && this.parentFingerPrint === obj.parentFingerPrint
      && this.childIndex === obj.childIndex
      && this.chainCode.equals(obj.chainCode)
      && this.privateKey.equals(obj.privateKey);
  }

  /**
   * Compare a key against an object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  compare(key) {
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
  }

  /**
   * Inject properties from seed.
   * @private
   * @param {Buffer} seed
   */

  fromSeed(seed) {
    assert(Buffer.isBuffer(seed));

    if (seed.length * 8 < common.MIN_ENTROPY
        || seed.length * 8 > common.MAX_ENTROPY) {
      throw new Error('Entropy not in range.');
    }

    const hash = sha512.mac(seed, SEED_SALT);
    const left = hash.slice(0, 32);
    const right = hash.slice(32, 64);

    // Only a 1 in 2^127 chance of happening.
    if (!secp256k1.privateKeyVerify(left))
      throw new Error('Master private key is invalid.');

    this.depth = 0;
    this.parentFingerPrint = 0;
    this.childIndex = 0;
    this.chainCode = right;
    this.privateKey = left;
    this.publicKey = secp256k1.publicKeyCreate(left, true);

    return this;
  }

  /**
   * Instantiate an hd private key from a 512 bit seed.
   * @param {Buffer} seed
   * @returns {HDPrivateKey}
   */

  static fromSeed(seed) {
    return new this().fromSeed(seed);
  }

  /**
   * Inject properties from a mnemonic.
   * @private
   * @param {Mnemonic} mnemonic
   * @param {String?} passphrase
   */

  fromMnemonic(mnemonic, passphrase) {
    assert(mnemonic instanceof Mnemonic);
    return this.fromSeed(mnemonic.toSeed(passphrase));
  }

  /**
   * Instantiate an hd private key from a mnemonic.
   * @param {Mnemonic} mnemonic
   * @param {String?} passphrase
   * @returns {HDPrivateKey}
   */

  static fromMnemonic(mnemonic, passphrase) {
    return new this().fromMnemonic(mnemonic, passphrase);
  }

  /**
   * Inject properties from a mnemonic.
   * @private
   * @param {String} mnemonic
   */

  fromPhrase(phrase) {
    const mnemonic = Mnemonic.fromPhrase(phrase);
    this.fromMnemonic(mnemonic);
    return this;
  }

  /**
   * Instantiate an hd private key from a phrase.
   * @param {String} phrase
   * @returns {HDPrivateKey}
   */

  static fromPhrase(phrase) {
    return new this().fromPhrase(phrase);
  }

  /**
   * Inject properties from privateKey and entropy.
   * @private
   * @param {Buffer} key
   * @param {Buffer} entropy
   */

  fromKey(key, entropy) {
    assert(Buffer.isBuffer(key) && key.length === 32);
    assert(Buffer.isBuffer(entropy) && entropy.length === 32);
    this.depth = 0;
    this.parentFingerPrint = 0;
    this.childIndex = 0;
    this.chainCode = entropy;
    this.privateKey = key;
    this.publicKey = secp256k1.publicKeyCreate(key, true);
    return this;
  }

  /**
   * Create an hd private key from a key and entropy bytes.
   * @param {Buffer} key
   * @param {Buffer} entropy
   * @returns {HDPrivateKey}
   */

  static fromKey(key, entropy) {
    return new this().fromKey(key, entropy);
  }

  /**
   * Generate an hd private key.
   * @returns {HDPrivateKey}
   */

  static generate() {
    const key = secp256k1.generatePrivateKey();
    const entropy = random.randomBytes(32);
    return HDPrivateKey.fromKey(key, entropy);
  }

  /**
   * Inject properties from base58 key.
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

    Network.fromPrivate(version, network);

    this.depth = br.readU8();
    this.parentFingerPrint = br.readU32BE();
    this.childIndex = br.readU32BE();
    this.chainCode = br.readBytes(32);
    assert(br.readU8() === 0);
    this.privateKey = br.readBytes(32);
    this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true);

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
   * Serialize key to a base58 string.
   * @param {(Network|NetworkType)?} network
   * @returns {Base58String}
   */

  toBase58(network) {
    return base58.encode(this.toRaw(network));
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    return 82;
  }

  /**
   * Write the key to a buffer writer.
   * @param {BufferWriter} bw
   * @param {(Network|NetworkType)?} network
   */

  toWriter(bw, network) {
    network = Network.get(network);

    bw.writeU32BE(network.keyPrefix.xprivkey);
    bw.writeU8(this.depth);
    bw.writeU32BE(this.parentFingerPrint);
    bw.writeU32BE(this.childIndex);
    bw.writeBytes(this.chainCode);
    bw.writeU8(0);
    bw.writeBytes(this.privateKey);
    bw.writeChecksum(hash256.digest);

    return bw;
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
   * Instantiate an HD private key from a base58 string.
   * @param {Base58String} xkey
   * @param {Network?} network
   * @returns {HDPrivateKey}
   */

  static fromBase58(xkey, network) {
    return new this().fromBase58(xkey, network);
  }

  /**
   * Instantiate key from buffer reader.
   * @param {BufferReader} br
   * @param {(Network|NetworkType)?} network
   * @returns {HDPrivateKey}
   */

  static fromReader(br, network) {
    return new this().fromReader(br, network);
  }

  /**
   * Instantiate key from serialized data.
   * @param {Buffer} data
   * @param {(Network|NetworkType)?} network
   * @returns {HDPrivateKey}
   */

  static fromRaw(data, network) {
    return new this().fromRaw(data, network);
  }

  /**
   * Convert key to a more json-friendly object.
   * @returns {Object}
   */

  toJSON(network) {
    return {
      xprivkey: this.xprivkey(network)
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @param {Network?} network
   */

  fromJSON(json, network) {
    assert(json.xprivkey, 'Could not handle key JSON.');

    this.fromBase58(json.xprivkey, network);

    return this;
  }

  /**
   * Instantiate an HDPrivateKey from a jsonified key object.
   * @param {Object} json - The jsonified key object.
   * @param {Network?} network
   * @returns {HDPrivateKey}
   */

  static fromJSON(json, network) {
    return new this().fromJSON(json, network);
  }

  /**
   * Test whether an object is an HDPrivateKey.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isHDPrivateKey(obj) {
    return obj instanceof HDPrivateKey;
  }
}

/*
 * Expose
 */

module.exports = HDPrivateKey;
