/*!
 * @module hd
 *
 * @description
 * HD mnemonics and keys (BIP32, BIP39) for bcoin.
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

var bcoin = require('./env');
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
var unorm;

/**
 * HD Mnemonic
 * @exports Mnemonic
 * @constructor
 * @param {Object} options
 * @param {Number?} options.bit - Bits of entropy (Must
 * be a multiple of 8) (default=128).
 * @param {Buffer?} options.entropy - Entropy bytes. Will
 * be generated with `options.bits` bits of entropy
 * if not present.
 * @param {String?} options.phrase - Mnemonic phrase (will
 * be generated if not present).
 * @param {String?} options.passphrase - Optional salt for
 * key stretching (empty string if not present).
 * @param {String?} options.language - Language.
 */

function Mnemonic(options) {
  if (!(this instanceof Mnemonic))
    return new Mnemonic(options);

  if (!options)
    options = {};

  this.bits = options.bits || 128;
  this.entropy = options.entropy;
  this.phrase = options.phrase;
  this.passphrase = options.passphrase || '';
  this.language = options.language || 'english';
  this.seed = options.seed;

  assert(this.bits >= 128);
  assert(this.bits % 32 === 0);
}

/**
 * Generate the seed.
 * @returns {Buffer} pbkdf2 seed.
 */

Mnemonic.prototype.toSeed = function toSeed() {
  if (this.seed)
    return this.seed;

  if (!this.phrase)
    this.phrase = this.createMnemonic();

  this.seed = utils.pbkdf2(
    nfkd(this.phrase),
    nfkd('mnemonic' + this.passphrase),
    2048,
    64);

  return this.seed;
};

/**
 * Generate a mnemonic phrase from chosen language.
 * @returns {String}
 */

Mnemonic.prototype.createMnemonic = function createMnemonic() {
  var mnemonic = [];
  var wordlist = Mnemonic.getWordlist(this.language);
  var i, j, bits, entropy, word, oct, bit;

  if (!this.entropy)
    this.entropy = ec.random(this.bits / 8);

  bits = this.entropy.length * 8;

  // Append the hash to the entropy to
  // make things easy when grabbing
  // the checksum bits.
  entropy = Buffer.concat([
    this.entropy,
    utils.sha256(this.entropy)
  ]);

  // Include the first `ENT / 32` bits
  // of the hash (the checksum).
  bits += bits / 32;

  // Build the mnemonic by reading
  // 11 bit indexes from the entropy.
  for (i = 0; i < bits; i++) {
    i--;
    word = 0;
    for (j = 0; j < 11; j++) {
      i++;
      bit = i % 8;
      oct = (i - bit) / 8;
      word <<= 1;
      word |= (entropy[oct] >>> (7 - bit)) & 1;
    }
    mnemonic.push(wordlist[word]);
  }

  // Japanese likes double-width spaces.
  if (this.language === 'japanese')
    return mnemonic.join('\u3000');

  return mnemonic.join(' ');
};

/**
 * Retrieve the wordlist for a language.
 * @param {String} language
 * @returns {String[]}
 */

Mnemonic.getWordlist = function getWordlist(language) {
  switch (language) {
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
      assert(false, 'Unknown language: ' + language);
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
    && typeof obj.toSeed === 'function';
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

function HD(options, network) {
  if (!options)
    return HD.fromMnemonic(null, network);
  return HD.fromAny(options, network);
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
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.generate = function generate(options, network) {
  return HDPrivateKey.generate(options, network);
};

/**
 * Generate an {@link HDPrivateKey} from a seed.
 * @param {Object|Mnemonic|Buffer} options - seed,
 * mnemonic, mnemonic options.
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.fromSeed = function fromSeed(options, network) {
  return HDPrivateKey.fromSeed(options, network);
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic|Object} mnemonic
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.fromMnemonic = function fromMnemonic(options, network) {
  return HDPrivateKey.fromMnemonic(options, network);
};

/**
 * Instantiate an HD key from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @param {String?} passphrase
 * @returns {HDPrivateKey}
 */

HD.fromJSON = function fromJSON(json, passphrase) {
  return HDPrivateKey.fromJSON(json, passphrase);
};

/**
 * Generate an hdkey from any number of options.
 * @param {Object|Mnemonic|Buffer} options - mnemonic, mnemonic
 * options, seed, or base58 key.
 * @param {String?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromAny = function fromAny(options, network) {
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

  return HDPrivateKey.fromMnemonic(options, network);
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
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Number?} max - Max index.
 * @returns {Number[]}
 */

HD.parsePath = function parsePath(path, max) {
  var parts = path.split('/');
  var root = parts.shift();
  var result = [];
  var i, hardened, index;

  if (max == null)
    max = constants.hd.MAX_INDEX;

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Bad path root.');
  }

  for (i = 0; i < parts.length; i++) {
    index = parts[i];
    hardened = index[index.length - 1] === '\'';

    if (hardened)
      index = index.slice(0, -1);

    if (!/^\d+$/.test(index))
      throw new Error('Non-number path index.');

    index = parseInt(index, 10);

    if (hardened)
      index += constants.hd.HARDENED;

    if (!(index >= 0 && index < max))
      throw new Error('Index out of range.');

    result.push(index);
  }

  return result;
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
 * @param {(Mnemonic|Object)?} options.mnemonic - mnemonic or mnemonic options.
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.privateKey
 * @property {String} network
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

  assert(options, 'No options for HD private key.');
  assert(options.depth <= 0xff, 'Depth is too high.');

  this.network = bcoin.network.get(options.network).type;
  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.privateKey = options.privateKey;

  this.publicKey = ec.publicKeyCreate(options.privateKey, true);
  this.fingerPrint = null;

  this.mnemonic = options.mnemonic;

  this._xprivkey = options.xprivkey;

  this.hdPrivateKey = this;
  this._hdPublicKey = null;
}

utils.inherits(HDPrivateKey, HD);

HDPrivateKey.prototype.__defineGetter__('hdPublicKey', function() {
  if (!this._hdPublicKey) {
    this._hdPublicKey = new HDPublicKey({
      network: this.network,
      depth: this.depth,
      parentFingerPrint: this.parentFingerPrint,
      childIndex: this.childIndex,
      chainCode: this.chainCode,
      publicKey: this.publicKey
    });
  }
  return this._hdPublicKey;
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
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation should be hardened.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derive = function derive(index, hardened) {
  var p, id, data, hash, left, chainCode, privateKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  id = this.xprivkey + '/' + index;
  child = HD.cache.get(id);

  if (child)
    return child;

  hardened = index >= constants.hd.HARDENED ? true : hardened;

  if (index < constants.hd.HARDENED && hardened)
    index += constants.hd.HARDENED;

  if (!(index >= 0 && index < constants.hd.MAX_INDEX))
    throw new Error('Index out of range.');

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

  hash = utils.hmac('sha512', data, this.chainCode);
  left = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = left
    .add(new bn(this.privateKey))
    .mod(ec.elliptic.curve.n)
    .toBuffer('be', 32);

  if (!this.fingerPrint)
    this.fingerPrint = utils.ripesha(this.publicKey).slice(0, 4);

  child = new HDPrivateKey({
    network: this.network,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    privateKey: privateKey
  });

  HD.cache.set(id, child);

  return child;
};

/**
 * Derive a BIP44 account key.
 * @param {Number} accountIndex
 * @returns {HDPrivateKey}
 * @throws Error if key is not a master key.
 */

HDPrivateKey.prototype.deriveAccount44 = function deriveAccount44(accountIndex) {
  var coinType;

  assert(utils.isNumber(accountIndex), 'Account index must be a number.');

  if (this instanceof HDPublicKey) {
    assert(this.isAccount44(accountIndex), 'Cannot derive account index.');
    return this;
  }

  assert(this.isMaster(), 'Cannot derive account index.');

  coinType = this.network === 'main' ? 0 : 1;

  return this
    .derive(44, true)
    .derive(coinType, true)
    .derive(accountIndex, true);
};

/**
 * Derive a BIP45 purpose key.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45() {
  var child;

  if (this instanceof HDPublicKey) {
    assert(this.isPurpose45(), 'Cannot derive purpose 45.');
    return this;
  }

  assert(this.isMaster(), 'Cannot derive purpose 45.');

  return this.derive(45, true);
};

/**
 * Test whether the key is a master key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isMaster = function isMaster() {
  return this.depth === 0
    && this.childIndex === 0
    && this.parentFingerPrint.readUInt32LE(0, true) === 0;
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @param {Number?} accountIndex
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isAccount44 = function isAccount44(accountIndex) {
  if (accountIndex != null) {
    if (this.childIndex !== constants.hd.HARDENED + accountIndex)
      return false;
  }
  return this.depth === 3 && this.childIndex >= constants.hd.HARDENED;
};

/**
 * Test whether the key is a BIP45 purpose key.
 * @returns {Boolean}
 */

HDPrivateKey.prototype.isPurpose45 = function isPurpose45() {
  return this.depth === 1 && this.childIndex === constants.hd.HARDENED + 45;
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
 * Test whether a string is a valid path.
 * @param {String} path
 * @param {Boolean?} hardened
 * @returns {Boolean}
 */

HDPrivateKey.isValidPath = function isValidPath(path) {
  if (typeof path !== 'string')
    return false;

  try {
    HD.parsePath(path, constants.hd.MAX_INDEX);
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
  var indexes = HD.parsePath(path, constants.hd.MAX_INDEX);
  var key = this;
  var i;

  for (i = 0; i < indexes.length; i++)
    key = key.derive(indexes[i]);

  return key;
};

/**
 * Create an hd private key from a seed.
 * @param {Buffer|Mnemonic|Object} options - A seed,
 * mnemonic, or mnemonic options.
 * @param {String?} network
 * @returns {Object} A "naked" key (a
 * plain javascript object which is suitable
 * for passing to the HDPrivateKey constructor).
 */

HDPrivateKey.parseSeed = function parseSeed(seed, network) {
  var hash, chainCode, privateKey;

  assert(Buffer.isBuffer(seed));

  if (seed.length < constants.hd.MIN_ENTROPY
      || seed.length > constants.hd.MAX_ENTROPY) {
    throw new Error('Entropy not in range.');
  }

  hash = utils.hmac('sha512', seed, 'Bitcoin seed');

  privateKey = hash.slice(0, 32);
  chainCode = hash.slice(32, 64);

  if (!ec.privateKeyVerify(privateKey))
    throw new Error('Master private key is invalid.');

  return {
    network: network,
    depth: 0,
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: 0,
    chainCode: chainCode,
    privateKey: privateKey
  };
};

/**
 * Instantiate an hd private key from a seed.
 * @param {Buffer|Mnemonic|Object} seed - A
 * seed, mnemonic, or mnemonic options.
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromSeed = function fromSeed(seed, network) {
  return new HDPrivateKey(HDPrivateKey.parseSeed(seed, network));
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic|Object} mnemonic
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromMnemonic = function fromMnemonic(mnemonic, network) {
  var key;

  if (!(mnemonic instanceof Mnemonic))
    mnemonic = new Mnemonic(mnemonic);

  if (mnemonic.seed || mnemonic.phrase || mnemonic.entropy) {
    key = HDPrivateKey.parseSeed(mnemonic.toSeed(), network);
    key.mnemonic = mnemonic;
    return new HDPrivateKey(key);
  }

  // Very unlikely, but not impossible
  // to get an invalid private key.
  for (;;) {
    try {
      key = HDPrivateKey.parseSeed(mnemonic.toSeed(), network);
      key.mnemonic = mnemonic;
      key = new HDPrivateKey(key);
    } catch (e) {
      if (e.message === 'Master private key is invalid.') {
        mnemonic.seed = null;
        mnemonic.phrase = null;
        mnemonic.entropy = null;
        continue;
      }
      throw e;
    }
    break;
  }

  return key;
};

/**
 * Generate an hd private key from a key and/or entropy bytes.
 * @param {Object?} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @param {String?} network
 * @returns {Object} A "naked" key (a
 * plain javascript object which is suitable
 * for passing to the HDPrivateKey constructor).
 */

HDPrivateKey._generate = function _generate(options, network) {
  var privateKey, entropy;

  if (!options)
    options = {};

  if (Buffer.isBuffer(options))
    options = { privateKey: options };

  privateKey = options.privateKey;
  entropy = options.entropy;

  if (!privateKey)
    privateKey = ec.generatePrivateKey();

  if (!entropy)
    entropy = ec.random(32);

  return {
    network: network,
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
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HDPrivateKey.generate = function generate(options, network) {
  return new HDPrivateKey(HDPrivateKey._generate(options, network));
};

/**
 * Parse a base58 extended private key.
 * @param {Base58String} xkey
 * @returns {Object}
 */

HDPrivateKey.parseBase58 = function parseBase58(xkey) {
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
 * Serialize key to a base58 string.
 * @param {Network|String} network
 * @returns {Base58String}
 */

HDPrivateKey.prototype.toBase58 = function toBase58(network) {
  var p = new BufferWriter();

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU32BE(network.prefixes.xprivkey);
  p.writeU8(this.depth);
  p.writeBytes(this.parentFingerPrint);
  p.writeU32BE(this.childIndex);
  p.writeBytes(this.chainCode);
  p.writeU8(0);
  p.writeBytes(this.privateKey);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Instantiate a transaction from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPrivateKey}
 */

HDPrivateKey.fromBase58 = function fromBase58(xkey) {
  return new HDPrivateKey(HDPrivateKey.parseBase58(xkey));
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
    network: this.network,
    encrypted: false
  };

  if (this instanceof HDPrivateKey) {
    json.encrypted = passphrase ? true : false;
    if (this.mnemonic) {
      json.phrase = passphrase
        ? utils.encrypt(this.mnemonic.phrase, passphrase).toString('hex')
        : this.mnemonic.phrase;
      json.passphrase = passphrase
        ? utils.encrypt(this.mnemonic.passphrase, passphrase).toString('hex')
        : this.mnemonic.passphrase;
    }
    json.xprivkey = passphrase
      ? utils.encrypt(this.xprivkey, passphrase).toString('hex')
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
    data.mnemonic = {
      phrase: json.encrypted
        ? utils.decrypt(json.phrase, passphrase).toString('utf8')
        : json.phrase,
      passphrase: json.encrypted
        ? utils.decrypt(json.passphrase, passphrase).toString('utf8')
        : json.passphrase
    };
    if (!json.xprivkey)
      return data;
  }

  if (json.xprivkey) {
    data.xprivkey = json.encrypted
      ? utils.decrypt(json.xprivkey, passphrase).toString('utf8')
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
    key.mnemonic = json.mnemonic ? new Mnemonic(json.mnemonic) : null;
    return key;
  }

  if (json.mnemonic)
    return HDPrivateKey.fromMnemonic(json.mnemonic, json.network);

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
  return obj
    && obj.hdPublicKey
    && obj.hdPublicKey !== obj
    && typeof obj.derive === 'function';
};

/**
 * HDPublicKey
 * @exports HDPublicKey
 * @constructor
 * @param {Object|Base58String} options
 * @param {Base58String?} options.xkey - Serialized base58 key.
 * @param {Number?} options.depth
 * @param {Buffer?} options.parentFingerPrint
 * @param {Number?} options.childIndex
 * @param {Buffer?} options.chainCode
 * @param {Buffer?} options.publicKey
 * @property {String} network
 * @property {Base58String} xpubkey
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

  this.network = bcoin.network.get(options.network).type;
  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.publicKey = options.publicKey;

  this.privateKey = null;
  this.fingerPrint = null;

  this.xprivkey = null;
  this._xpubkey = options.xpubkey;

  this.hdPublicKey = this;
  this.hdPrivateKey = null;
}

utils.inherits(HDPublicKey, HD);

HDPublicKey.prototype.__defineGetter__('xpubkey', function() {
  if (!this._xpubkey)
    this._xpubkey = this.toBase58();
  return this._xpubkey;
});

/**
 * Derive a child key.
 * @param {Number|String} - Child index or path.
 * @param {Boolean?} hardened - Whether the derivation
 * should be hardened (throws if true).
 * @returns {HDPrivateKey}
 * @throws on `hardened`
 */

HDPublicKey.prototype.derive = function derive(index, hardened) {
  var p, id, data, hash, left, chainCode;
  var publicPoint, point, publicKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  id = this.xpubkey + '/' + index;
  child = HD.cache.get(id);

  if (child)
    return child;

  if (index >= constants.hd.HARDENED || hardened)
    throw new Error('Index out of range.');

  if (index < 0)
    throw new Error('Index out of range.');

  p = new BufferWriter();
  p.writeBytes(this.publicKey);
  p.writeU32BE(index);
  data = p.render();

  hash = utils.hmac('sha512', data, this.chainCode);
  left = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  publicPoint = ec.elliptic.curve.decodePoint(this.publicKey);
  point = ec.elliptic.curve.g.mul(left).add(publicPoint);
  publicKey = new Buffer(point.encode('array', true));
  assert(publicKey.length === 33);

  if (!this.fingerPrint)
    this.fingerPrint = utils.ripesha(this.publicKey).slice(0, 4);

  child = new HDPublicKey({
    network: this.network,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    publicKey: publicKey
  });

  HD.cache.set(id, child);

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
 * Test whether the key is a master key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isMaster = HDPrivateKey.prototype.isMaster;

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @method
 * @param {Number?} accountIndex
 * @returns {Boolean}
 */

HDPublicKey.prototype.isAccount44 = HDPrivateKey.prototype.isAccount44;

/**
 * Test whether the key is a BIP45 purpose key.
 * @method
 * @returns {Boolean}
 */

HDPublicKey.prototype.isPurpose45 = HDPrivateKey.prototype.isPurpose45;

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
    HD.parsePath(path, constants.hd.HARDENED);
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
  var indexes = HD.parsePath(path, constants.hd.HARDENED);
  var key = this;
  var i;

  for (i = 0; i < indexes.length; i++)
    key = key.derive(indexes[i]);

  return key;
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

HDPublicKey.parseBase58 = function parseBase58(xkey) {
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
 * @param {Network|String} network
 * @returns {Base58String}
 */

HDPublicKey.prototype.toBase58 = function toBase58(network) {
  var p = new BufferWriter();

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU32BE(network.prefixes.xpubkey);
  p.writeU8(this.depth);
  p.writeBytes(this.parentFingerPrint);
  p.writeU32BE(this.childIndex);
  p.writeBytes(this.chainCode);
  p.writeBytes(this.publicKey);
  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Instantiate a transaction from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPublicKey}
 */

HDPublicKey.fromBase58 = function fromBase58(xkey) {
  return new HDPublicKey(HDPublicKey.parseBase58(xkey));
};

/**
 * Test an object to see if it is a HDPublicKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.isHDPublicKey = function isHDPublicKey(obj) {
  return obj
    && obj.hdPublicKey
    && obj.hdPublicKey === obj
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

HDPrivateKey.prototype.toSecret = function toSecret(network) {
  return KeyPair.prototype.toSecret.call(this, network);
};

/*
 * Helpers
 */

function nfkd(str) {
  if (str.normalize)
    return str.normalize('NFKD');

  if (!unorm)
    unorm = require('../../vendor/unorm');

  return unorm.nfkd(str);
}

/*
 * Expose
 */

HD.Mnemonic = Mnemonic;
HD.PrivateKey = HDPrivateKey;
HD.PublicKey = HDPublicKey;

module.exports = HD;
