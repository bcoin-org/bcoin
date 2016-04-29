/*!
 * @module hd
 *
 * @description
 * HD seeds and keys (BIP32, BIP39) for bcoin.
 * Code adapted from bitcore-lib:
 * - {@link https://github.com/bitpay/bitcore-lib/blob/master/lib/hdprivatekey.js}
 * - {@link https://github.com/bitpay/bitcore-lib/blob/master/lib/hdpublickey.js}
 * - {@link https://github.com/ryanxcharles/fullnode/blob/master/lib/bip32.js}
 * - {@link https://github.com/bitpay/bitcore-mnemonic/blob/master/lib/mnemonic.js}
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * @license
 *
 * BIP32
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 *
 * Copyright (c) 2013-2015 BitPay, Inc.
 *
 * Parts of this software are based on Bitcoin Core
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 *
 * Parts of this software are based on fullnode
 * Copyright (c) 2014 Ryan X. Charles
 * Copyright (c) 2014 reddit, Inc.
 *
 * Parts of this software are based on BitcoinJS
 * Copyright (c) 2011 Stefan Thomas <justmoon@members.fsf.org>
 *
 * Parts of this software are based on BitcoinJ
 * Copyright (c) 2011 Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * BIP39
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 BitPay
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

module.exports = function(bcoin) {

var bn = require('bn.js');
var utils = require('./utils');
var ec = require('./ec');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var KeyPair = bcoin.keypair;
var LRU = require('./lru');
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var unorm = require('../../vendor/unorm');

/**
 * HD Seed
 * @exports Mnemonic
 * @constructor
 * @param {Object} options
 * @param {Number?} options.bit - Bits of entropy (Must
 * be a multiple of 8) (default=128).
 * @param {Buffer?} options.entropy - Entropy bytes. Will
 * be generated with `options.bits` bits of entropy
 * if not present.
 * @param {String?} options.mnemonic - Mnemonic string (will
 * be generated if not present).
 * @param {String?} options.passphrase - Optional salt for
 * key stretching (empty string if not present).
 * @param {String?} options.lang - Language.
 */

function Mnemonic(options) {
  if (!(this instanceof Mnemonic))
    return new Mnemonic(options);

  if (!options)
    options = {};

  if (Buffer.isBuffer(options)) {
    this.seed = options;
    options = {};
  } else {
    this.seed = null;
  }

  this.bits = options.bits || 128;
  this.entropy = options.entropy;
  this.phrase = options.phrase;
  this.passphrase = options.passphrase || '';
  this.lang = options.lang || 'english';

  assert(this.bits >= 128);
  assert(this.bits % 32 === 0);
}

/**
 * Generate the seed.
 * @returns {Buffer} pbkdf2 seed.
 */

Mnemonic.prototype.createSeed = function createSeed() {
  if (this.seed)
    return this.seed;

  if (!this.entropy)
    this.entropy = ec.random(this.bits / 8);
  else
    this.bits = this.entropy.length * 8;

  if (!this.phrase)
    this.phrase = this.createMnemonic();

  this.seed = utils.pbkdf2(
    unorm.nfkd(this.phrase),
    unorm.nfkd('mnemonic' + this.passphrase),
    2048, 64);

  return this.seed;
};

/**
 * Generate mnemonic string from english words.
 * @returns {String}
 */

Mnemonic.prototype.createMnemonic = function createMnemonic() {
  var bin = '';
  var mnemonic = [];
  var wordlist = Mnemonic.getWordlist(this.lang);
  var i, wi, hash, bits;

  for (i = 0; i < this.entropy.length; i++)
    bin += ('00000000' + this.entropy[i].toString(2)).slice(-8);

  hash = utils.sha256(this.entropy);
  bits = new bn(hash).toString(2);
  while (bits.length % 256 !== 0)
    bits = '0' + bits;

  bin += bits.slice(0, this.bits / 32);

  assert(bin.length % 11 === 0);

  for (i = 0; i < bin.length / 11; i++) {
    wi = parseInt(bin.slice(i * 11, (i + 1) * 11), 2);
    mnemonic.push(wordlist[wi]);
  }

  if (this.lang === 'japanese')
    return mnemonic.join('\u3000');

  return mnemonic.join(' ');
};

/**
 * Retrieve the wordlist for a language.
 * @param {String} lang
 * @returns {String[]}
 */

Mnemonic.getWordlist = function getWordlist(lang) {
  switch (lang) {
    case 'simplified chinese':
      return require('../../etc/chinese-simplified.js');
    case 'traditional chinese':
      return require('../../etc/chinese-traditional.js');
    case 'english':
      return require('../../etc/english.js');
    case 'french':
      return require('../../etc/french.js');
    case 'italian':
      return require('../../etc/italian.js');
    case 'japanese':
      return require('../../etc/japanese.js');
    default:
      assert(false, 'Unknown language: ' + lang);
  }
};

/**
 * Test an object to see if it is an Mnemonic.
 * @param {Object} obj
 * @returns {Boolean}
 */

Mnemonic.isMnemonic = function isMnemonic(obj) {
  return obj
    && typeof obj.bits === 'number'
    && typeof obj.createSeed === 'function';
};

/**
 * HD - Abstract class for HD keys. Will
 * potentially return an {@link HDPublicKey}
 * or {@link HDPrivateKey}.
 * @exports HD
 * @abstract
 * @constructor
 * @param {Object} options - {@link HDPublicKey}
 * or {@link HDPrivateKey} options.
 */

function HD(options) {
  if (!options)
    return HD.fromSeed();
  return HD.fromAny(options);
}

/**
 * Instantiate an HD key (public or private) from an base58 string.
 * @param {Base58String} xkey
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromBase58 = function fromBase58(xkey) {
  if (HDPrivateKey.isExtended(xkey))
    return HDPrivateKey.fromBase58(xkey);
  return HDPublicKey.fromBase58(xkey);
};

/**
 * Generate an {@link HDPrivateKey}.
 * @param {Object} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @param {String?} networkType
 * @returns {HDPrivateKey}
 */

HD.generate = function generate(options, networkType) {
  return HDPrivateKey.generate(options, networkType);
};

/**
 * Generate an {@link HDPrivateKey} from a seed.
 * @param {Object|Mnemonic} options - HD seed or HD seed options.
 * @param {String?} networkType
 * @returns {HDPrivateKey}
 */

HD.fromSeed = function fromSeed(options, networkType) {
  return HDPrivateKey.fromSeed(options, networkType);
};

/**
 * Generate an hdkey from any number of options.
 * @param {Object|Mnemonic} options - HD seed, HD seed
 * options, buffer seed, or base58 key.
 * @param {String?} networkType
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromAny = function fromAny(options, networkType) {
  var xkey;

  assert(options, 'Options required.');

  if (options.xkey)
    xkey = options.xkey;
  else if (options.xpubkey)
    xkey = options.xpubkey;
  else if (options.xprivkey)
    xkey = options.xprivkey;
  else
    xkey = options;

  if (HDPrivateKey.isExtended(xkey))
    return HDPrivateKey.fromBase58(xkey);

  if (HDPublicKey.isExtended(xkey))
    return HDPublicKey.fromBase58(xkey);

  return HDPrivateKey.fromSeed(options, networkType);
};

/**
 * Test whether an object is in the form of a base58 hd key.
 * @param {String} data
 * @returns {Boolean}
 */

HD.isExtended = function isExtended(data) {
  return HDPrivateKey.isExtended(data)
    || HDPublicKey.isExtended(data);
};

/**
 * LRU cache to avoid deriving keys twice.
 * @type {LRU}
 */

HD.cache = new LRU(500);

/**
 * Test an object to see if it is an HD key.
 * @param {Object} obj
 * @returns {Boolean}
 */

HD.isHD = function isHD(obj) {
  return HDPrivateKey.isHDPrivateKey(obj)
    || HDPublicKey.isHDPublicKey(obj);
};

/**
 * HDPrivateKey
 * @exports HDPrivateKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {(Mnemonic|Object)?} options.seed - HD seed or HD seed options.
 * @param {Number?} options.version
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.privateKey
 * @property {String} network
 * @property {Base58String} xprivkey
 * @property {Base58String} xpubkey
 * @property {Mnemonic?} seed
 * @property {Number} version
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

  assert(options, 'No options for HD private key.');
  assert(options.depth <= 0xff, 'Depth is too high.');

  this.network = options.network || network.type;
  this.xprivkey = options.xprivkey;
  this.seed = options.seed;

  this.version = options.version;
  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.privateKey = options.privateKey;

  this.publicKey = ec.publicKeyCreate(options.privateKey, true);
  this.fingerPrint = null;

  this.hdPrivateKey = this;

  if (!this.xprivkey)
    this.xprivkey = HDPrivateKey.render(options);
}

utils.inherits(HDPrivateKey, HD);

HDPrivateKey.prototype.__defineGetter__('hdPublicKey', function() {
  if (!this._hdPublicKey) {
    this._hdPublicKey = new HDPublicKey({
      network: this.network,
      version: network[this.network].prefixes.xpubkey,
      depth: this.depth,
      parentFingerPrint: this.parentFingerPrint,
      childIndex: this.childIndex,
      chainCode: this.chainCode,
      publicKey: this.publicKey
    });
  }
  return this._hdPublicKey;
});

HDPrivateKey.prototype.__defineGetter__('xpubkey', function() {
  return this.hdPublicKey.xpubkey;
});

/**
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation should be hardened.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derive = function derive(index, hardened) {
  var cached, p, data, hash, leftPart, chainCode, privateKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xprivkey + '/' + index);

  if (cached)
    return cached;

  hardened = index >= constants.hd.HARDENED ? true : hardened;
  if (index < constants.hd.HARDENED && hardened)
    index += constants.hd.HARDENED;

  p = new BufferWriter();

  if (hardened) {
    p.writeU8(0);
    p.writeBytes(this.privateKey);
    p.writeU32BE(index);
  } else {
    p.writeBytes(this.publicKey);
    p.writeU32BE(index);
  }

  data = p.render();

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = leftPart
    .add(new bn(this.privateKey))
    .mod(ec.elliptic.curve.n)
    .toBuffer('be', 32);

  if (!this.fingerPrint) {
    this.fingerPrint = utils.ripesha(this.publicKey)
      .slice(0, constants.hd.PARENT_FINGERPRINT_SIZE);
  }

  child = new HDPrivateKey({
    network: this.network,
    version: this.version,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    privateKey: privateKey
  });

  HD.cache.set(this.xprivkey + '/' + index, child);

  return child;
};

/**
 * Derive a BIP44 account key.
 * @param {Number} accountIndex
 * @returns {HDPrivateKey}
 * @throws Error if key is not a master key.
 */

HDPrivateKey.prototype.deriveAccount44 = function deriveAccount44(options) {
  var coinType, accountIndex, child;

  if (typeof options === 'number')
    options = { accountIndex: options };

  coinType = options.coinType;
  accountIndex = options.accountIndex;

  if (this instanceof HDPublicKey) {
    assert(this.isAccount44());
    return this;
  }

  if (coinType == null)
    coinType = this.network === 'main' ? 0 : 1;

  assert(utils.isFinite(coinType));
  assert(utils.isFinite(accountIndex));

  child = this
    .derive(44, true)
    .derive(coinType, true)
    .derive(accountIndex, true);

  assert(child.isAccount44());

  return child;
};

/**
 * Derive a BIP45 purpose key.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45() {
  var child;

  if (this instanceof HDPublicKey) {
    assert(this.isPurpose45());
    return this;
  }

  child = this.derive(45, true);

  assert(child.isPurpose45());

  return child;
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isPurpose45 = function isPurpose45() {
  if (this.depth !== 1)
    return false;
  return this.childIndex === constants.hd.HARDENED + 45;
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isAccount44 = function isAccount44() {
  if (this.childIndex < constants.hd.HARDENED)
    return false;
  return this.depth === 3;
};

/**
 * Test whether an object is in the form of a base58 xprivkey.
 * @param {String} data
 * @returns {Boolean}
 */

HDPrivateKey.isExtended = function isExtended(data) {
  var i, type, prefix;

  if (typeof data !== 'string')
    return false;

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xprivkey58;
    if (data.indexOf(prefix) === 0)
      return true;
  }

  return false;
};

/**
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @returns {Number[]}
 */

HDPrivateKey._getIndexes = function _getIndexes(path) {
  var steps = path.split('/');
  var root = steps.shift();
  var indexes = [];
  var i, step, hardened, index;

  if (~constants.hd.PATH_ROOTS.indexOf(path))
    return indexes;

  if (!~constants.hd.PATH_ROOTS.indexOf(root))
    return null;

  for (i = 0; i < steps.length; i++) {
    step = steps[i];
    hardened = step[step.length - 1] === '\'';

    if (hardened)
      step = step.slice(0, -1);

    if (!step || step[0] === '-')
      return null;

    index = +step;

    if (hardened)
      index += constants.hd.HARDENED;

    indexes.push(index);
  }

  return indexes;
};

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPrivateKey.isValidPath = function isValidPath(path, hardened) {
  var indexes;

  if (typeof path === 'string') {
    indexes = HDPrivateKey._getIndexes(path);
    return indexes !== null && indexes.every(HDPrivateKey.isValidPath);
  }

  if (typeof path === 'number') {
    if (path < constants.hd.HARDENED && hardened)
      path += constants.hd.HARDENED;
    return path >= 0 && path < constants.hd.MAX_INDEX;
  }

  return false;
};

/**
 * Derive a key from a derivation path.
 * @param {String} path
 * @returns {HDPrivateKey}
 * @throws Error if `path` is not a valid path.
 */

HDPrivateKey.prototype.derivePath = function derivePath(path) {
  var indexes;

  if (!HDPrivateKey.isValidPath(path))
    throw new Error('Invalid path.');

  indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  }, this);
};

/**
 * Create an hd private key from a seed.
 * @param {Buffer|Mnemonic|Object} options - A buffer, HD seed, or HD seed options.
 * @param {String?} networkType
 * @returns {Object} A "naked" key (a
 * plain javascript object which is suitable
 * for passing to the HDPrivateKey constructor).
 */

HDPrivateKey.parseSeed = function parseSeed(seed, networkType) {
  var data, hash;

  if (!seed)
    seed = {};

  if (Buffer.isBuffer(seed)) {
    data = seed;
    seed = null;
  } else if (seed instanceof Mnemonic) {
    data = seed.createSeed();
  } else {
    seed = new Mnemonic(seed);
    data = seed.createSeed();
  }

  if (data.length < constants.hd.MIN_ENTROPY
      || data.length > constants.hd.MAX_ENTROPY) {
    throw new Error('Entropy not in range.');
  }

  hash = utils.sha512hmac(data, 'Bitcoin seed');

  return {
    version: networkType
      ? network[networkType].prefixes.xprivkey
      : network.prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: 0,
    chainCode: hash.slice(32, 64),
    privateKey: hash.slice(0, 32),
    seed: seed
  };
};

/**
 * Instantiate a transaction from an HD seed.
 * @param {Buffer|Mnemonic|Object} seed - A buffer, HD seed, or HD seed options.
 * @param {String?} networkType
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromSeed = function fromSeed(seed, networkType) {
  return new HDPrivateKey(HDPrivateKey.parseSeed(seed, networkType));
};

/**
 * Generate an hd private key from a key and/or entropy bytes.
 * @param {Object?} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @param {String?} networkType
 * @returns {Object} A "naked" key (a
 * plain javascript object which is suitable
 * for passing to the HDPrivateKey constructor).
 */

HDPrivateKey._generate = function _generate(options, networkType) {
  if (!options)
    opitons = {};

  if (Buffer.isBuffer(options))
    options = { privateKey: options };

  if (!options.privateKey)
    options.privateKey = ec.generatePrivateKey();

  if (!options.entropy)
    options.entropy = ec.random(32);

  return {
    version: networkType
      ? network[networkType].prefixes.xprivkey
      : network.prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: 0,
    chainCode: entropy,
    privateKey: privateKey
  };
};

/**
 * Generate an hd private key from a key and/or entropy bytes.
 * @param {Object?} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @param {String?} networkType
 * @returns {HDPrivateKey}
 */

HDPrivateKey.generate = function generate(options, networkType) {
  return new HDPrivateKey(HDPrivateKey._generate(options, networkType));
};

/**
 * Parse a base58 extended private key.
 * @param {Base58String} xkey
 * @returns {Object}
 */

HDPrivateKey.parse = function parse(xkey) {
  var raw = utils.fromBase58(xkey);
  var p = new BufferReader(raw, true);
  var data = {};
  var i, type, prefix;

  data.version = p.readU32BE();
  data.depth = p.readU8();
  data.parentFingerPrint = p.readBytes(4);
  data.childIndex = p.readU32BE();
  data.chainCode = p.readBytes(32);
  p.readU8();
  data.privateKey = p.readBytes(32);
  p.verifyChecksum();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xprivkey;
    if (data.version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  data.network = type;
  data.xprivkey = xkey;

  return data;
};

/**
 * Instantiate a transaction from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromBase58 = function fromBase58(xkey) {
  var data = HDPrivateKey.parse(xkey);
  return new HDPrivateKey(data);
};

/**
 * Serialize key data to base58 extended key.
 * @param {Object|HDPrivateKey}
 * @returns {Base58String}
 */

HDPrivateKey.render = function render(data) {
  var p = new BufferWriter();
  p.writeU32BE(data.version);
  p.writeU8(data.depth);
  p.writeBytes(data.parentFingerPrint);
  p.writeU32BE(data.childIndex);
  p.writeBytes(data.chainCode);
  p.writeU8(0);
  p.writeBytes(data.privateKey);
  p.writeChecksum();
  return utils.toBase58(p.render());
};

/**
 * Convert key to a more json-friendly object.
 * @param {String?} passphrase - Address passphrase
 * @returns {Object}
 */

HDPrivateKey.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'hdkey',
    encrypted: false
  };

  if (this instanceof HDPrivateKey) {
    json.encrypted = passphrase ? true : false;
    if (this.seed) {
      json.phrase = passphrase
        ? utils.encrypt(this.seed.phrase, passphrase)
        : this.seed.phrase;
      json.passphrase = passphrase
        ? utils.encrypt(this.seed.passphrase, passphrase)
        : this.seed.passphrase;
      json.lang = this.seed.lang;
    }
    json.xprivkey = passphrase
      ? utils.encrypt(this.xprivkey, passphrase)
      : this.xprivkey;
    return json;
  }

  json.xpubkey = this.xpubkey;

  return json;
};

/**
 * Handle a deserialized JSON HDPrivateKey object.
 * @param {Object} json
 * @returns {Object} A "naked" HDPrivateKey.
 */

HDPrivateKey.parseJSON = function parseJSON(json, passphrase) {
  var data = {};

  assert.equal(json.v, 1);
  assert.equal(json.name, 'hdkey');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt address');

  if (json.phrase) {
    data.seed = {
      phrase: json.encrypted
        ? utils.decrypt(json.phrase, passphrase)
        : json.phrase,
      passphrase: json.encrypted
        ? utils.decrypt(json.passphrase, passphrase)
        : json.passphrase,
      lang: json.lang
    };
    if (!json.xprivkey)
      return data;
  }

  if (json.xprivkey) {
    data.xprivkey = json.encrypted
      ? utils.decrypt(json.xprivkey, passphrase)
      : json.xprivkey;
    return data;
  }

  if (json.xpubkey) {
    return {
      xpubkey: json.xpubkey
    };
  }

  assert(false);
};

/**
 * Instantiate an HDPrivateKey from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @param {String?} passphrase
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromJSON = function fromJSON(json, passphrase) {
  var key;

  json = HDPrivateKey.parseJSON(json, passphrase);

  if (json.xprivkey) {
    key = HDPrivateKey.fromBase58(json.xprivkey);
    key.seed = json.seed ? new Mnemonic(json.seed) : null;
    return key;
  }

  if (json.seed)
    return HDPrivateKey.fromSeed(json.seed);

  if (json.xpubkey)
    return HDPublicKey.fromBase58(json.xprivkey);

  assert(false, 'Could not handle HD key JSON.');
};

/**
 * Test an object to see if it is a HDPrivateKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.isHDPrivateKey = function isHDPrivateKey(obj) {
  return obj && obj.xprivkey && typeof obj.derive === 'function';
};

/**
 * HDPublicKey
 * @exports HDPublicKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Number?} options.version
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.publicKey
 * @property {String} network
 * @property {Base58String} xpubkey
 * @property {Number} version
 * @property {Number} depth
 * @property {Buffer} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} publicKey
 */

function HDPublicKey(options) {
  if (!(this instanceof HDPublicKey))
    return new HDPublicKey(options);

  assert(options, 'No options for HDPublicKey');
  assert(options.depth <= 0xff, 'Depth is too high.');

  this.network = options.network || network.type;
  this.xpubkey = options.xpubkey;
  this.xprivkey = null;

  this.version = options.version;
  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.publicKey = options.publicKey;

  this.privateKey = null;
  this.fingerPrint = null;

  this.hdPublicKey = this;
  this.hdPrivateKey = null;

  if (!this.xpubkey)
    this.xpubkey = HDPublicKey.render(options);
}

utils.inherits(HDPublicKey, HD);

/**
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation
 * should be hardened (throws if true).
 * @returns {HDPrivateKey}
 * @throws on `hardened`
 */

HDPublicKey.prototype.derive = function derive(index, hardened) {
  var cached, p, data, hash, leftPart, chainCode;
  var publicPoint, point, publicKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xpubkey + '/' + index);

  if (cached)
    return cached;

  if (index >= constants.hd.HARDENED || hardened)
    throw new Error('Invalid index.');

  if (index < 0)
    throw new Error('Invalid path.');

  p = new BufferWriter();
  p.writeBytes(this.publicKey);
  p.writeU32BE(index);
  data = p.render();

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  publicPoint = ec.elliptic.curve.decodePoint(this.publicKey);
  point = ec.elliptic.curve.g.mul(leftPart).add(publicPoint);
  publicKey = new Buffer(point.encode('array', true));
  assert(publicKey.length === 33);

  if (!this.fingerPrint) {
    this.fingerPrint = utils.ripesha(this.publicKey)
      .slice(0, constants.hd.PARENT_FINGERPRINT_SIZE);
  }

  child = new HDPublicKey({
    network: this.network,
    version: this.version,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    publicKey: publicKey
  });

  HD.cache.set(this.xpubkey + '/' + index, child);

  return child;
};

/**
 * Derive a BIP44 account key (does not derive, only ensures account key).
 * @method
 * @param {Number} accountIndex
 * @returns {HDPublicKey}
 * @throws Error if key is not already an account key.
 */

HDPublicKey.prototype.deriveAccount44 = HDPrivateKey.prototype.deriveAccount44;

/**
 * Derive a BIP45 purpose key (does not derive, only ensures account key).
 * @method
 * @returns {HDPublicKey}
 * @throws Error if key is not already a purpose key.
 */

HDPublicKey.prototype.derivePurpose45 = HDPrivateKey.prototype.derivePurpose45;

/**
 * Test whether the key is a BIP45 purpose key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isPurpose45 = HDPrivateKey.prototype.isPurpose45;

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isAccount44 = HDPrivateKey.prototype.isAccount44;

/**
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPublicKey.isValidPath = function isValidPath(arg) {
  var indexes;

  if (typeof arg === 'string') {
    indexes = HDPrivateKey._getIndexes(arg);
    return indexes !== null && indexes.every(HDPublicKey.isValidPath);
  }

  if (typeof arg === 'number')
    return arg >= 0 && arg < constants.hd.HARDENED;

  return false;
};

/**
 * Derive a key from a derivation path.
 * @param {String} path
 * @returns {HDPublicKey}
 * @throws Error if `path` is not a valid path.
 * @throws Error if hardened.
 */

HDPublicKey.prototype.derivePath = function derivePath(path) {
  var indexes;

  if (path.indexOf('\'') !== -1)
    throw new Error('Cannot derive hardened.');

  if (!HDPublicKey.isValidPath(path))
    throw new Error('Invalid path.');

  indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  }, this);
};

/**
 * Convert key to a more json-friendly object.
 * @method
 * @returns {Object}
 */

HDPublicKey.prototype.toJSON = HDPrivateKey.prototype.toJSON;

/**
 * Handle a deserialized JSON HDPublicKey object.
 * @param {Object} json
 * @returns {Object} A "naked" HDPublicKey.
 */

HDPublicKey.parseJSON = HDPrivateKey.parseJSON;

/**
 * Instantiate an HDPrivateKey from a jsonified key object.
 * @method
 * @param {Object} json - The jsonified transaction object.
 * @returns {HDPrivateKey}
 */

HDPublicKey.fromJSON = HDPrivateKey.fromJSON;

/**
 * Test whether an object is in the form of a base58 xpubkey.
 * @param {String} data
 * @returns {Boolean}
 */

HDPublicKey.isExtended = function isExtended(data) {
  var i, type, prefix;

  if (typeof data !== 'string')
    return false;

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xpubkey58;
    if (data.indexOf(prefix) === 0)
      return true;
  }

  return false;
};

/**
 * Parse a base58 extended public key.
 * @param {Base58String} xkey
 * @returns {Object}
 */

HDPublicKey.parse = function parse(xkey) {
  var raw = utils.fromBase58(xkey);
  var p = new BufferReader(raw, true);
  var data = {};
  var i, type, prefix;

  data.version = p.readU32BE();
  data.depth = p.readU8();
  data.parentFingerPrint = p.readBytes(4);
  data.childIndex = p.readU32BE();
  data.chainCode = p.readBytes(32);
  data.publicKey = p.readBytes(33);
  p.verifyChecksum();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xpubkey;
    if (data.version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  data.network = type;
  data.xpubkey = xkey;

  return data;
};

/**
 * Serialize key data to base58 extended key.
 * @param {Object|HDPublicKey}
 * @returns {Base58String}
 */

HDPublicKey.render = function render(data) {
  var p = new BufferWriter();
  p.writeU32BE(data.version);
  p.writeU8(data.depth);
  p.writeBytes(data.parentFingerPrint);
  p.writeU32BE(data.childIndex);
  p.writeBytes(data.chainCode);
  p.writeBytes(data.publicKey);
  p.writeChecksum();
  return utils.toBase58(p.render());
};

/**
 * Instantiate a transaction from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPublicKey}
 */

HDPublicKey.fromBase58 = function fromBase58(xkey) {
  var data = HDPublicKey.parse(xkey);
  return new HDPublicKey(data);
};

/**
 * Test an object to see if it is a HDPublicKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.isHDPublicKey = function isHDPublicKey(obj) {
  return obj
    && obj.xpubkey
    && !obj.xprivkey
    && typeof obj.derive === 'function';
};

[HDPrivateKey, HDPublicKey].forEach(function(HD) {
  /**
   * Get private key.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @returns {Buffer}
   */

  HD.prototype.getPrivateKey = function getPrivateKey() {
    return KeyPair.prototype.getPrivateKey.apply(this, arguments);
  };

  /**
   * Get public key.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @returns {Buffer}
   */

  HD.prototype.getPublicKey = function getPublicKey() {
    return KeyPair.prototype.getPublicKey.apply(this, arguments);
  };

  /**
   * Sign message.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @param {Buffer} msg
   * @returns {Buffer}
   */

  HD.prototype.sign = function sign() {
    return KeyPair.prototype.sign.apply(this, arguments);
  };

  /**
   * Verify message.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @param {Buffer} msg
   * @param {Buffer} sig
   * @returns {Buffer}
   */

  HD.prototype.verify = function verify() {
    return KeyPair.prototype.verify.apply(this, arguments);
  };

  HD.prototype.compressed = true;
});

/**
 * Convert HDPrivateKey to CBitcoinSecret.
 * @returns {Base58String}
 */

HDPrivateKey.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret.call(this);
};

HD.seed = Mnemonic;
HD.priv = HDPrivateKey;
HD.pub = HDPublicKey;
HD.privateKey = HDPrivateKey;
HD.publicKey = HDPublicKey;
HD.fromJSON = HDPrivateKey.fromJSON;

return HD;
};
