/*!
 * keyprovider.js - parsed key object for descriptor in bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const HD = require('../hd/hd');
const KeyRing = require('../primitives/keyring');
const {scriptContext, isHex} = require('./common');
const Network = require('../protocol/network');

/**
 * Constants
 */

/**
 * Derive type for a key in a descriptor
 * @const {Object}
 */

const deriveType = {
  NO: 'NO',
  UNHARDENED: 'UNHARDENED',
  HARDENED: 'HARDENED'
};

/**
 * KeyProvider
 * Base class for key object in a descriptor.
 * @alias module:descriptor.KeyProvider
 * @property {KeyRing} ring
 * @property {Network} network
 * @property {KeyOriginInfo} originInfo - key origin information
 * @property {String} hardenedMarker - hardened marker for derivation path
 * default is `h`
 */

class KeyProvider {
  /**
   * @constructor
   */

  constructor() {
    this.ring = null;
    this.network = null;
    this.originInfo = null;
    this.hardenedMarker = 'h';
  }

  parseOptions(options) {
    this.ring = options.ring;
    this.originInfo = options.originInfo;
    this.hardenedMarker = options.hardenedMarker;
    this.network = Network.get(options.network);
  }

  /**
   * Get the key object.
   * @param {String} keyString
   * @param {String?} context - script context
   * @returns {ConstKeyProvider|HDKeyProvider}
   */

  _parseKey(keyString, context) {
    const keySplit = keyString.split('/'); // split the key and derivation path
    assert(keySplit.length > 0 && keySplit[0] !== '', 'No key provided');

    const str = keySplit[0];

    /**
     * Check whether uncompressed keys are allowed or not.
     * permit is true if uncompressed keys are allowed.
     */

    const permit = [scriptContext.TOP, scriptContext.P2SH].includes(context);

    if (keySplit.length === 1) {
      let ring = null;

      if (isHex(str)) {
        ring = KeyRing.fromPublic(Buffer.from(str, 'hex')); // pubkey (hex)
      } else if (!HD.isBase58(str, this.network)) {
        ring = KeyRing.fromSecret(str, this.network); // privkey (WIF)
      }

      if (ring) {
        assert(
          permit || ring.publicKey.length === 33,
          'Uncompressed keys are not allowed'
        );

        return new ConstKeyProvider({
          originInfo: this.originInfo,
          ring,
          hardenedMarker: this.hardenedMarker,
          network: this.network
        });
      }
    }

    // xpriv or xpub (including derivation path if any) -> HDKeyProvider
    const hdkey = HD.fromBase58(str, this.network);
    const key = hdkey.privateKey || hdkey.publicKey;
    const ring = KeyRing.fromKey(key);

    let type = deriveType.NO;
    const last = keySplit[keySplit.length - 1];

    if (last === '*') {
      type = deriveType.UNHARDENED;
      keySplit.pop();
    } else if ((last === '*\'' || last === '*h')) {
      this.hardenedMarker = last[last.length - 1];
      type = deriveType.HARDENED;
      keySplit.pop();
    }

    const pathArray = keySplit.slice(1);
    const marker = getHardenedMarker(pathArray);

    if (marker) {
      this.hardenedMarker = marker;
    }

    const path = HD.common.parsePathFromArray(pathArray, true);

    return new HDKeyProvider({
      originInfo: this.originInfo,
      ring,
      hdkey,
      path,
      type,
      hardenedMarker: this.hardenedMarker,
      network: this.network
    });
  }

  /**
   * Get the parsed key object including the key origin info
   * (if available)
   * @param {String} keyExpr
   * @param {String?} context script context
   * @returns {ConstKeyProvider|HDKeyProvider}
   * @throws parse error
   */

  parseKey(keyExpr, context) {
    // split the key and origin info
    const originSplit = keyExpr.split(']');
    assert(
      originSplit.length <= 2,
      'Multiple ] characters found for a single pubkey'
    );

    // key with no origin info
    if (originSplit.length === 1) {
      const keyString = originSplit[0];
      return this._parseKey(keyString, context);
    }

    // key with origin info
    assert(
      originSplit.length && originSplit[0][0] === '[',
      `Key origin start expected '[', found ${originSplit[0][0]} instead`
    );

    const originInfoString = originSplit[0].slice(1); // remove starting '['
    const originPathArray = originInfoString.split('/').slice(1);

    const marker = getHardenedMarker(originPathArray);
    if (marker) {
      this.hardenedMarker = marker;
    }

    const originInfo = HD.KeyOriginInfo.fromString(originInfoString);
    const keyString = originSplit[1]; // key with derivation path (if any)
    this.originInfo = originInfo;

    return this._parseKey(keyString, context);
  }

  /**
   * Inject properties from string
   * @param {String} keyExpr
   * @param {Network} network
   * @param {String?} context script context
   * @returns {ConstKeyProvider|HDKeyProvider}
   */

  fromString(keyExpr, network, context) {
    this.network = Network.get(network);
    return this.parseKey(keyExpr, context);
  }

  /**
   * Instantiate KeyProvider from string.
   * @param {String} keyExpr
   * @param {Network} network
   * @param {String?} context script context
   * @returns {ConstKeyProvider|HDKeyProvider}
   */

  static fromString(keyExpr, network, context = scriptContext.TOP) {
    return new this().fromString(keyExpr, network, context);
  }

  /**
   * Get the string form of the origin info path (if available)
   * @returns {String}
   */

  getOriginString() {
    if (this.originInfo) {
      return `[${this.originInfo.toString(this.hardenedMarker)}]`;
    }
    return '';
  }

  /**
   * Test whether this represent multiple keys at different positions
   * @returns {Boolean}
   */

  isRange() {
    return false;
  }

  /**
   * Get the size of the generated public key(s) in bytes
   * @returns {Number} 33 or 65
   */

  getSize() {
    throw new Error('Abstract method.');
  }

  /**
   * Get the string form of the public key
   * @returns {String}
   */

  toString() {
    throw new Error('Abstract method.');
  }

  /**
   * Get the string form of the private key (if available)
   * @returns {String}
   */

  toPrivateString() {
    throw new Error('Abstract method.');
  }

  /**
   * Test whether this key provider has private key
   * @returns {Boolean}
   */

  hasPrivateKey() {
    return this.ring.privateKey !== null;
  }

  /**
   * Get the public key
   * @returns {Buffer}
   */

  getPublicKey() {
    return this.ring.publicKey;
  }

  /**
   * Get the private key (if available)
   * @returns {Buffer}
   */

  getPrivateKey() {
    return this.ring.privateKey;
  }
}

/**
 * ConstKeyProvider
 * Represents a non-hd key object with origin info (if any) in a descriptor
 * @extends KeyProvider
 */

class ConstKeyProvider extends KeyProvider {
  constructor(options) {
    super();

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {ConstKeyProvider}
   */

  fromOptions(options) {
    this.parseOptions(options);

    return this;
  }

  /**
   * Instantiate ConstKeyProvider from options object.
   * @param {Object} options
   * @returns {ConstKeyProvider}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  getSize() {
    return this.ring.publicKey.length;
  }

  toString() {
    return this.getOriginString() + this.ring.getPublicKey('hex');
  }

  toPrivateString() {
    const privKey = this.ring.getPrivateKey('base58', this.network);
    if (privKey) {
      return this.getOriginString() + privKey;
    }
    return null;
  }
}

/**
 * HDKeyProvider
 * Represents an hd key object with origin info (if any) in a descriptor
 * @property {HDPublicKey|HDPrivateKey} hdkey
 * @property {Number[]} path - array of derivation indices
 * @property {String} type - derivation type - Normal, Hardened, or Unhardened
 * @extends KeyProvider
 */

class HDKeyProvider extends KeyProvider {
  constructor(options) {
    super();

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object
   * @param {Object} options
   * @returns {HDKeyProvider}
   */

  fromOptions(options) {
    this.parseOptions(options);

    this.hdkey = options.hdkey;
    this.path = options.path;
    this.type = options.type;

    return this;
  }

  /**
   * Instantiate HDKeyProvider from options object
   * @param {Object} options
   * @returns {HDKeyProvider}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  isRange() {
    return this.type !== deriveType.NO;
  }

  /**
   * Test whether the derivation path is normal, hardened, unhardened
   * @returns {Boolean}
   */

  isHardened() {
    return (
      this.path.some(index => index & HD.common.HARDENED) ||
      this.type === deriveType.HARDENED
    );
  }

  getSize() {
    return 33;
  }

  _toString(key) {
    const path = HD.common.format(this.path, this.hardenedMarker);
    let result = `${key}${path}`;
    if (this.isRange()) {
      result += '/*';
      if (this.type === deriveType.HARDENED) {
        result += this.hardenedMarker;
      }
    }
    return result;
  }

  toString() {
    const key = this.hdkey.xpubkey(this.network);
    return this.getOriginString() + this._toString(key);
  }

  toPrivateString() {
    const key = this.hdkey.xprivkey(this.network);
    if (key) {
      return this.getOriginString() + this._toString(key);
    }
    return null;
  }

  /**
   * Derive private key at a given position..
   * @returns {HDPrivateKey}
   */

  getHDPrivateKey(pos) {
    assert(
      this.hdkey.privateKey,
      'Private key not available for hardened derivation.'
    );

    let childkey = this.hdkey;

    if (this.path.length > 0) {
      const path = 'm' + HD.common.format(this.path, this.hardenedMarker);
      childkey = childkey.derivePath(path);
    }

    if (this.type === deriveType.UNHARDENED) {
      childkey = childkey.derive(pos, false);
    } else if (this.type === deriveType.HARDENED) {
      childkey = childkey.derive(pos, true);
    }

    return childkey;
  }

  /**
   * Derive public key at a given position
   * @param {Number} pos
   * @returns {HDPublicKey}
   */

  getHDPublicKey(pos) {
    if (this.isHardened()) {
      const childprivkey = this.getHDPrivateKey(pos);
      return childprivkey.toPublic();
    }

    let childkey = this.hdkey;

    if (this.hdkey instanceof HD.PrivateKey) {
      childkey = this.hdkey.toPublic();
    }

    if (this.path.length > 0) {
      const path = 'm' + HD.common.format(this.path, this.hardenedMarker);
      childkey = childkey.derivePath(path);
    }

    if (this.type === deriveType.UNHARDENED) {
      childkey = childkey.derive(pos);
    }

    assert(this.type !== deriveType.HARDENED);

    return childkey;
  }

  /**
   * Get public key at a given position
   * @param {Number} pos
   * @returns {Buffer} public key
   */

  getPublicKey(pos) {
    const hdkey = this.getHDPublicKey(pos);
    return hdkey.publicKey;
  }

  /**
   * Get private key at a given position
   * @param {Number} pos
   * @returns {Buffer} private key
   */

  getPrivateKey(pos) {
    const hdkey = this.getHDPrivateKey(pos);
    return hdkey.privateKey;
  }
}

/**
 * Helpers
 */

/**
 * Get the hardened marker at the last hardened step in a path
 * @param {Array} path
 * @returns {String} `'`, `h`, or null
 */

function getHardenedMarker(path) {
  assert(Array.isArray(path));

  let hardenedMarker = null;
  for (const p of path) {
    const last = p[p.length - 1];
    if (last === '\'' || last === 'h') {
      hardenedMarker = last;
    }
  }
  return hardenedMarker;
};

/**
 * Expose
 */

module.exports = KeyProvider;
