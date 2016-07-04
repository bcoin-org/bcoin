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
 * https://github.com/bcoin-org/bcoin
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

'use strict';

var bcoin = require('./env');
var bn = require('bn.js');
var utils = require('./utils');
var ec = require('./ec');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var networks = bcoin.protocol.network;
var KeyPair = bcoin.keypair;
var LRU = require('./lru');
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var unorm;

/*
 * Constants
 */

var PUBLIC_KEY = new Buffer(33);
PUBLIC_KEY.fill(0);

var FINGER_PRINT = new Buffer(4);
FINGER_PRINT.fill(0);

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

  this.bits = constants.hd.MIN_ENTROPY;
  this.language = 'english';
  this.entropy = null;
  this.phrase = null;
  this.passphrase = '';

  if (options)
    this.fromOptions(options);
}

/**
 * List of languages.
 * @const {String[]}
 * @default
 */

Mnemonic.languages = [
  'simplified chinese',
  'traditional chinese',
  'english',
  'french',
  'italian',
  'japanese'
];

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Mnemonic.prototype.fromOptions = function fromOptions(options) {
  if (typeof options === 'string')
    options = { phrase: options };

  if (options.bits != null) {
    assert(utils.isNumber(options.bits));
    assert(options.bits >= constants.hd.MIN_ENTROPY);
    assert(options.bits <= constants.hd.MAX_ENTROPY);
    assert(options.bits % 32 === 0);
    this.bits = options.bits;
  }

  if (options.language) {
    assert(typeof options.language === 'string');
    assert(Mnemonic.languages.indexOf(options.language) !== -1);
    this.language = options.language;
  }

  if (options.passphrase) {
    assert(typeof options.passphrase === 'string');
    this.passphrase = options.passphrase;
  }

  if (options.phrase) {
    this.fromPhrase(options.phrase);
    return this;
  }

  if (options.entropy) {
    this.fromEntropy(options.entropy);
    return this;
  }

  return this;
};

/**
 * Instantiate mnemonic from options.
 * @param {Object} options
 * @returns {Mnemonic}
 */

Mnemonic.fromOptions = function fromOptions(options) {
  return new Mnemonic().fromOptions(options);
};

/**
 * Generate the seed.
 * @param {String?} passphrase
 * @returns {Buffer} pbkdf2 seed.
 */

Mnemonic.prototype.toSeed = function toSeed(passphrase) {
  if (!passphrase)
    passphrase = this.passphrase;

  this.passphrase = passphrase;

  return utils.pbkdf2Sync(
    nfkd(this.getPhrase()),
    nfkd('mnemonic' + passphrase),
    2048, 64, 'sha512');
};

/**
 * Generate seed and create an hd private key.
 * @param {String?} passphrase
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey}
 */

Mnemonic.prototype.toKey = function toKey(passphrase, network) {
  var seed = this.toSeed(passphrase);
  var key = HDPrivateKey.fromSeed(seed, network);
  key.mnemonic = this;
  return key;
};

/**
 * Get or generate entropy.
 * @returns {Buffer}
 */

Mnemonic.prototype.getEntropy = function getEntropy() {
  if (!this.entropy)
    this.entropy = ec.random(this.bits / 8);

  assert(this.bits / 8 === this.entropy.length);

  return this.entropy;
};

/**
 * Generate a mnemonic phrase from chosen language.
 * @returns {String}
 */

Mnemonic.prototype.getPhrase = function getPhrase() {
  var i, j, phrase, wordlist, bits, entropy, index, pos, oct, bit;

  if (this.phrase)
    return this.phrase;

  phrase = [];
  wordlist = Mnemonic.getWordlist(this.language);

  entropy = this.getEntropy();
  bits = this.bits;

  // Append the hash to the entropy to
  // make things easy when grabbing
  // the checksum bits.
  entropy = Buffer.concat([entropy, utils.sha256(entropy)]);

  // Include the first `ENT / 32` bits
  // of the hash (the checksum).
  bits += bits / 32;

  // Build the mnemonic by reading
  // 11 bit indexes from the entropy.
  for (i = 0; i < bits / 11; i++) {
    index = 0;
    for (j = 0; j < 11; j++) {
      pos = i * 11 + j;
      bit = pos % 8;
      oct = (pos - bit) / 8;
      index <<= 1;
      index |= (entropy[oct] >>> (7 - bit)) & 1;
    }
    phrase.push(wordlist[index]);
  }

  // Japanese likes double-width spaces.
  if (this.language === 'japanese')
    phrase = phrase.join('\u3000');
  else
    phrase = phrase.join(' ');

  this.phrase = phrase;

  return phrase;
};

/**
 * Inject properties from phrase.
 * @private
 * @param {String} phrase
 */

Mnemonic.prototype.fromPhrase = function fromPhrase(phrase) {
  var i, j, bits, pos, oct, bit, b, ent, entropy, lang;
  var chk, word, wordlist, index, cbits, cbytes, words;

  assert(typeof phrase === 'string');

  words = phrase.split(/[ \u3000]+/);
  bits = words.length * 11;
  cbits = bits % 32;
  cbytes = Math.ceil(cbits / 8);
  bits -= cbits;

  assert(bits >= constants.hd.MIN_ENTROPY);
  assert(bits <= constants.hd.MAX_ENTROPY);
  assert(bits % 32 === 0);
  assert(cbits !== 0, 'Invalid checksum.');

  ent = new Buffer(Math.ceil((bits + cbits) / 8));
  ent.fill(0);

  lang = Mnemonic.getLanguage(words[0]);
  wordlist = Mnemonic.getWordlist(lang);

  for (i = 0; i < words.length; i++) {
    word = words[i];
    index = wordlist.indexOf(word);

    if (index === -1)
      throw new Error('Could not find word.');

    for (j = 0; j < 11; j++) {
      pos = i * 11 + j;
      bit = pos % 8;
      oct = (pos - bit) / 8;
      b = (index >>> (10 - j)) & 1;
      ent[oct] |= b << (7 - bit);
    }
  }

  entropy = ent.slice(0, ent.length - cbytes);
  ent = ent.slice(ent.length - cbytes);
  chk = utils.sha256(entropy);

  for (i = 0; i < cbits; i++) {
    bit = i % 8;
    oct = (i - bit) / 8;
    b = (ent[oct] >>> (7 - bit)) & 1;
    j = (chk[oct] >>> (7 - bit)) & 1;
    if (b !== j)
      throw new Error('Invalid checksum.');
  }

  assert(bits / 8 === entropy.length);

  this.bits = bits;
  this.language = lang;
  this.entropy = entropy;
  this.phrase = phrase;

  return this;
};

/**
 * Instantiate mnemonic from a phrase (validates checksum).
 * @param {String} phrase
 * @returns {Mnemonic}
 * @throws on bad checksum
 */

Mnemonic.fromPhrase = function fromPhrase(phrase) {
  return new Mnemonic().fromPhrase(phrase);
};

/**
 * Inject properties from entropy.
 * @private
 * @param {Buffer} entropy
 * @param {String?} lang
 */

Mnemonic.prototype.fromEntropy = function fromEntropy(entropy, lang) {
  assert(Buffer.isBuffer(entropy));
  assert(entropy.length * 8 >= constants.hd.MIN_ENTROPY);
  assert(entropy.length * 8 <= constants.hd.MAX_ENTROPY);
  assert((entropy.length * 8) % 32 === 0);
  assert(!lang || Mnemonic.languages.indexOf(lang) !== -1);

  this.entropy = entropy;
  this.bits = entropy.length * 8;

  if (lang)
    this.language = lang;

  return this;
};

/**
 * Instantiate mnemonic from entropy.
 * @param {Buffer} entropy
 * @param {String?} lang
 * @returns {Mnemonic}
 */

Mnemonic.fromEntropy = function fromEntropy(entropy, lang) {
  return new Mnemonic().fromEntropy(entropy, lang);
};

/**
 * Determine a single word's language.
 * @param {String} word
 * @returns {String} Language.
 * @throws on not found.
 */

Mnemonic.getLanguage = function getLanguage(word) {
  var i, lang, wordlist;

  for (i = 0; i < Mnemonic.languages.length; i++) {
    lang = Mnemonic.languages[i];
    wordlist = Mnemonic.getWordlist(lang);
    if (wordlist.indexOf(word) !== -1)
      return lang;
  }

  throw new Error('Could not determine language.');
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
      throw new Error('Unknown language: ' + language);
  }
};

/**
 * Convert mnemonic to a json-friendly object.
 * @returns {Object}
 */

Mnemonic.prototype.toJSON = function toJSON() {
  return {
    bits: this.bits,
    language: this.language,
    entropy: this.getEntropy().toString('hex'),
    phrase: this.getPhrase(),
    passphrase: this.passphrase
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Mnemonic.prototype.fromJSON = function fromJSON(json) {
  assert(utils.isNumber(json.bits));
  assert(typeof json.language === 'string');
  assert(typeof json.entropy === 'string');
  assert(typeof json.phrase === 'string');
  assert(typeof json.passphrase === 'string');
  assert(json.bits >= constants.hd.MIN_ENTROPY);
  assert(json.bits <= constants.hd.MAX_ENTROPY);
  assert(json.bits % 32 === 0);
  assert(json.bits / 8 === json.entropy.length / 2);

  this.bits = json.bits;
  this.language = json.language;
  this.entropy = new Buffer(json.entropy, 'hex');
  this.phrase = json.phrase;
  this.passphrase = json.passphrase;

  return this;
};

/**
 * Instantiate mnemonic from json object.
 * @param {Object} json
 * @returns {Mnemonic}
 */

Mnemonic.fromJSON = function fromJSON(json) {
  return new Mnemonic().fromJSON(json);
};

/**
 * Serialize mnemonic.
 * @returns {Buffer}
 */

Mnemonic.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var lang = Mnemonic.languages.indexOf(this.language);

  assert(lang !== -1);

  p.writeU16(this.bits);
  p.writeU8(lang);
  p.writeBytes(this.getEntropy());
  p.writeVarString(this.getPhrase(), 'utf8');
  p.writeVarString(this.passphrase, 'utf8');

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Mnemonic.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);

  this.bits = p.readU16();
  this.language = Mnemonic.languages[p.readU8()];
  this.entropy = p.readBytes(this.bits / 8);
  this.phrase = p.readVarString('utf8');
  this.passphrase = p.readVarString('utf8');

  assert(this.language);
  assert(this.bits >= constants.hd.MIN_ENTROPY);
  assert(this.bits <= constants.hd.MAX_ENTROPY);
  assert(this.bits % 32 === 0);

  return this;
};

/**
 * Instantiate mnemonic from serialized data.
 * @param {Buffer} data
 * @returns {Mnemonic}
 */

Mnemonic.fromRaw = function fromRaw(data) {
  return new Mnemonic().fromRaw(data);
};

/**
 * Convert the mnemonic to a string.
 * @returns {String}
 */

Mnemonic.prototype.toString = function toString() {
  return this.getPhrase();
};

/**
 * Inspect the mnemonic.
 * @returns {String}
 */

Mnemonic.prototype.inspect = function inspect() {
  return '<Mnemonic: ' + this.getPhrase() + '>';
};

/**
 * Test whether an object is a Mnemonic.
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
  return HD.from(options, network);
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
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromJSON = function fromJSON(json) {
  if (json.xprivkey)
    return HDPrivateKey.fromJSON(json);
  return HDPublicKey.fromJSON(json);
};

/**
 * Instantiate an HD key from serialized data.
 * @param {Buffer} data
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromRaw = function fromRaw(data) {
  if (HDPrivateKey.hasPrefix(data))
    return HDPrivateKey.fromRaw(data);
  return HDPublicKey.fromRaw(data);
};

/**
 * Instantiate HD key from extended serialized data.
 * @param {Buffer} data
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromExtended = function fromExtended(data) {
  if (HDPrivateKey.hasPrefix(data))
    return HDPrivateKey.fromExtended(data);
  return HDPublicKey.fromRaw(data);
};

/**
 * Generate an hdkey from any number of options.
 * @param {Object|Mnemonic|Buffer} options - mnemonic, mnemonic
 * options, seed, or base58 key.
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.from = function from(options, network) {
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

  if (HD.isExtended(xkey))
    return HD.fromBase58(xkey);

  if (HD.hasPrefix(options))
    return HD.fromRaw(options);

  return HD.fromMnemonic(options, network);
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
 * Test whether an object is in the form of a serialized hd key.
 * @param {Buffer} data
 * @returns {NetworkType}
 */

HD.hasPrefix = function hasPrefix(data) {
  return HDPrivateKey.hasPrefix(data)
    || HDPublicKey.hasPrefix(data);
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
 * Test whether an object is an HD key.
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

  this.network = bcoin.network.get();
  this.depth = 0;
  this.parentFingerPrint = FINGER_PRINT;
  this.childIndex = 0;
  this.chainCode = constants.ZERO_HASH;
  this.privateKey = constants.ZERO_HASH;

  this.publicKey = PUBLIC_KEY;
  this.fingerPrint = null;

  this.mnemonic = null;

  this._xprivkey = null;

  this.hdPrivateKey = this;
  this._hdPublicKey = null;

  if (options)
    this.fromOptions(options);
}

utils.inherits(HDPrivateKey, HD);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

HDPrivateKey.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'No options for HD private key.');
  assert(utils.isNumber(options.depth));
  assert(Buffer.isBuffer(options.parentFingerPrint));
  assert(utils.isNumber(options.childIndex));
  assert(Buffer.isBuffer(options.chainCode));
  assert(Buffer.isBuffer(options.privateKey));
  assert(options.depth <= 0xff, 'Depth is too high.');

  if (options.network)
    this.network = bcoin.network.get(options.network);

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

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

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
    .mod(ec.curve.n)
    .toArrayLike(Buffer, 'be', 32);

  // Only a 1 in 2^127 chance of happening.
  if (!ec.privateKeyVerify(privateKey))
    throw new Error('Private key is invalid.');

  if (!this.fingerPrint)
    this.fingerPrint = utils.hash160(this.publicKey).slice(0, 4);

  child = new HDPrivateKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = chainCode;
  child.privateKey = privateKey;
  child.publicKey = ec.publicKeyCreate(privateKey, true);

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
  assert(utils.isNumber(accountIndex), 'Account index must be a number.');
  assert(this.isMaster(), 'Cannot derive account index.');
  return this
    .derive(44, true)
    .derive(this.network.type === 'main' ? 0 : 1, true)
    .derive(accountIndex, true);
};

/**
 * Derive a BIP45 purpose key.
 * @returns {HDPrivateKey}
 */

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45() {
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

HDPrivateKey.hasPrefix = function hasPrefix(data) {
  var i, version, prefix, type;

  if (!Buffer.isBuffer(data))
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
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPrivateKey.prototype.equal = function equal(obj) {
  if (!HDPrivateKey.isHDPrivateKey(obj))
    return false;

  return this.network === obj.network
    && this.depth === obj.depth
    && utils.equal(this.parentFingerPrint, obj.parentFingerPrint)
    && this.childIndex === obj.childIndex
    && utils.equal(this.chainCode, obj.chainCode)
    && utils.equal(this.privateKey, obj.privateKey);
};

/**
 * Inject properties from seed.
 * @private
 * @param {Buffer} seed
 * @param {(Network|NetworkType)?} network
 */

HDPrivateKey.prototype.fromSeed = function fromSeed(seed, network) {
  var hash, chainCode, privateKey;

  assert(Buffer.isBuffer(seed));

  if (!(seed.length * 8 >= constants.hd.MIN_ENTROPY
      && seed.length * 8 <= constants.hd.MAX_ENTROPY)) {
    throw new Error('Entropy not in range.');
  }

  hash = utils.hmac('sha512', seed, 'Bitcoin seed');

  privateKey = hash.slice(0, 32);
  chainCode = hash.slice(32, 64);

  // Only a 1 in 2^127 chance of happening.
  if (!ec.privateKeyVerify(privateKey))
    throw new Error('Master private key is invalid.');

  this.network = bcoin.network.get(network);
  this.depth = 0;
  this.parentFingerPrint = new Buffer([0, 0, 0, 0]);
  this.childIndex = 0;
  this.chainCode = chainCode;
  this.privateKey = privateKey;
  this.publicKey = ec.publicKeyCreate(this.privateKey, true);

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
  this.network = bcoin.network.get(network);
  this.depth = 0;
  this.parentFingerPrint = new Buffer([0, 0, 0, 0]);
  this.childIndex = 0;
  this.chainCode = entropy;
  this.privateKey = key;
  this.publicKey = ec.publicKeyCreate(this.privateKey, true);
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
  var entropy = ec.random(32);
  return HDPrivateKey.fromKey(key, entropy, network);
};

/**
 * Inject properties from base58 key.
 * @private
 * @param {Base58String} xkey
 */

HDPrivateKey.prototype.fromBase58 = function fromBase58(xkey) {
  this.fromRaw(utils.fromBase58(xkey));
  this._xprivkey = xkey;
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

HDPrivateKey.prototype.fromRaw = function fromRaw(raw) {
  var p = new BufferReader(raw);
  var i, version, type, prefix;

  version = p.readU32BE();
  this.depth = p.readU8();
  this.parentFingerPrint = p.readBytes(4);
  this.childIndex = p.readU32BE();
  this.chainCode = p.readBytes(32);
  p.readU8();
  this.privateKey = p.readBytes(32);
  p.verifyChecksum();

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xprivkey;
    if (version === prefix)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

  this.publicKey = ec.publicKeyCreate(this.privateKey, true);
  this.network = bcoin.network.get(type);

  return this;
};

/**
 * Serialize key to a base58 string.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

HDPrivateKey.prototype.toBase58 = function toBase58(network) {
  return utils.toBase58(this.toRaw(network));
};

/**
 * Serialize the key.
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPrivateKey.prototype.toRaw = function toRaw(network, writer) {
  var p = new BufferWriter(writer);

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU32BE(network.keyPrefix.xprivkey);
  p.writeU8(this.depth);
  p.writeBytes(this.parentFingerPrint);
  p.writeU32BE(this.childIndex);
  p.writeBytes(this.chainCode);
  p.writeU8(0);
  p.writeBytes(this.privateKey);
  p.writeChecksum();

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize the key in "extended"
 * format (includes the mnemonic).
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

HDPrivateKey.prototype.toExtended = function toExtended(network, writer) {
  var p = new BufferWriter(writer);

  this.toRaw(network, p);

  if (this.mnemonic) {
    p.writeU8(1);
    this.mnemonic.toRaw(p);
  } else {
    p.writeU8(0);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from extended serialized data.
 * @private
 * @param {Buffer} data
 */

HDPrivateKey.prototype.fromExtended = function fromExtended(data) {
  var p = new BufferReader(data);
  this.fromRaw(p);
  if (p.readU8() === 1)
    this.mnemonic = Mnemonic.fromRaw(p);
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
 * @property {Network} network
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

  this.network = bcoin.network.get();
  this.depth = 0;
  this.parentFingerPrint = FINGER_PRINT;
  this.childIndex = 0;
  this.chainCode = constants.ZERO_HASH;
  this.publicKey = PUBLIC_KEY;

  this.fingerPrint = null;

  this._xpubkey = null;

  this.hdPublicKey = this;
  this.hdPrivateKey = null;

  if (options)
    this.fromOptions(options);
}

utils.inherits(HDPublicKey, HD);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

HDPublicKey.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'No options for HDPublicKey');
  assert(utils.isNumber(options.depth));
  assert(Buffer.isBuffer(options.parentFingerPrint));
  assert(utils.isNumber(options.childIndex));
  assert(Buffer.isBuffer(options.chainCode));
  assert(Buffer.isBuffer(options.publicKey));

  if (options.network)
    this.network = bcoin.network.get(options.network);

  this.depth = options.depth;
  this.parentFingerPrint = options.parentFingerPrint;
  this.childIndex = options.childIndex;
  this.chainCode = options.chainCode;
  this.publicKey = options.publicKey;

  if (options.xpubkey) {
    assert(typeof options.xpubkey === 'string');
    this._xpubkey = options.xpubkey;
  }

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
  var p, id, data, hash, left, chainCode, point, publicKey, child;

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

  if (this.depth >= 0xff)
    throw new Error('Depth too high.');

  p = new BufferWriter();
  p.writeBytes(this.publicKey);
  p.writeU32BE(index);
  data = p.render();

  hash = utils.hmac('sha512', data, this.chainCode);
  left = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  point = ec.decodePoint(this.publicKey);
  point = ec.curve.g.mul(left).add(point);
  publicKey = new Buffer(point.encode('array', true));
  assert(publicKey.length === 33);

  if (!ec.publicKeyVerify(publicKey))
    throw new Error('Public key is invalid.');

  if (!this.fingerPrint)
    this.fingerPrint = utils.hash160(this.publicKey).slice(0, 4);

  child = new HDPublicKey();
  child.network = this.network;
  child.depth = this.depth + 1;
  child.parentFingerPrint = this.fingerPrint;
  child.childIndex = index;
  child.chainCode = chainCode;
  child.publicKey = publicKey;

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
 * Compare a key against an object.
 * @param {Object} obj
 * @returns {Boolean}
 */

HDPublicKey.prototype.equal = function equal(obj) {
  if (!HDPublicKey.isHDPublicKey(obj))
    return false;

  return this.network === obj.network
    && this.depth === obj.depth
    && utils.equal(this.parentFingerPrint, obj.parentFingerPrint)
    && this.childIndex === obj.childIndex
    && utils.equal(this.chainCode, obj.chainCode)
    && utils.equal(this.publicKey, obj.publicKey);
};

/**
 * Convert key to a more json-friendly object.
 * @returns {Object}
 */

HDPublicKey.prototype.toJSON = function toJSON() {
  return {
    xpubkey: this.xpubkey
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

HDPublicKey.prototype.fromJSON = function fromJSON(json) {
  assert(json.xpubkey, 'Could not handle HD key JSON.');
  this.fromBase58(json.xpubkey);
  return this;
};

/**
 * Instantiate an HDPrivateKey from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {HDPrivateKey}
 */

HDPublicKey.fromJSON = function fromJSON(json) {
  return new HDPublicKey().fromJSON(json);
};

/**
 * Test whether an object is in the form of a base58 xpubkey.
 * @param {String} data
 * @returns {Boolean}
 */

HDPublicKey.isExtended = function isExtended(data) {
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

HDPublicKey.hasPrefix = function hasPrefix(data) {
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
 */

HDPublicKey.prototype.fromBase58 = function fromBase58(xkey) {
  this.fromRaw(utils.fromBase58(xkey));
  this._xpubkey = xkey;
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} raw
 */

HDPublicKey.prototype.fromRaw = function fromRaw(raw) {
  var p = new BufferReader(raw);
  var i, version, type, prefix;

  version = p.readU32BE();
  this.depth = p.readU8();
  this.parentFingerPrint = p.readBytes(4);
  this.childIndex = p.readU32BE();
  this.chainCode = p.readBytes(32);
  this.publicKey = p.readBytes(33);
  p.verifyChecksum();

  for (i = 0; i < networks.types.length; i++) {
    type = networks.types[i];
    prefix = networks[type].keyPrefix.xpubkey;
    if (version === prefix)
      break;
  }

  assert(i < networks.types.length, 'Network not found.');

  this.network = bcoin.network.get(type);

  return this;
};

/**
 * Serialize key data to base58 extended key.
 * @param {Network|String} network
 * @returns {Base58String}
 */

HDPublicKey.prototype.toBase58 = function toBase58(network) {
  return utils.toBase58(this.toRaw(network));
};

/**
 * Serialize the key.
 * @param {Network|NetworkType} network
 * @returns {Buffer}
 */

HDPublicKey.prototype.toRaw = function toRaw(network, writer) {
  var p = new BufferWriter(writer);

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU32BE(network.keyPrefix.xpubkey);
  p.writeU8(this.depth);
  p.writeBytes(this.parentFingerPrint);
  p.writeU32BE(this.childIndex);
  p.writeBytes(this.chainCode);
  p.writeBytes(this.publicKey);
  p.writeChecksum();

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Instantiate an HD public key from a base58 string.
 * @param {Base58String} xkey
 * @returns {HDPublicKey}
 */

HDPublicKey.fromBase58 = function fromBase58(xkey) {
  return new HDPublicKey().fromBase58(xkey);
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

[HDPrivateKey, HDPublicKey].forEach(function(HD) {
  /**
   * Get private key.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @method
   * @returns {Buffer}
   */

  HD.prototype.getPrivateKey = KeyPair.prototype.getPrivateKey;

  /**
   * Get public key.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @method
   * @returns {Buffer}
   */

  HD.prototype.getPublicKey = KeyPair.prototype.getPublicKey;

  /**
   * Sign message.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @param {Buffer} msg
   * @returns {Buffer}
   */

  HD.prototype.sign = KeyPair.prototype.sign;

  /**
   * Verify message.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @param {Buffer} msg
   * @param {Buffer} sig
   * @returns {Boolean}
   */

  HD.prototype.verify = KeyPair.prototype.verify;

  /**
   * Whether the key prefers a
   * compressed public key.
   * Always true.
   * @memberof HDPrivateKey#
   * @memberof HDPublicKey#
   * @type {Boolean}
   */

  HD.prototype.compressed = true;
});

/**
 * Convert HDPrivateKey to a KeyPair.
 * @returns {KeyPair}
 */

HDPrivateKey.prototype.toKeyPair = function toKeyPair() {
  return new KeyPair(this);
};

/**
 * Convert HDPrivateKey to CBitcoinSecret.
 * @returns {Base58String}
 */

HDPrivateKey.prototype.toSecret = function toSecret(network) {
  return this.toKeyPair().toSecret(network);
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

exports = HD;
exports.Mnemonic = Mnemonic;
exports.PrivateKey = HDPrivateKey;
exports.PublicKey = HDPublicKey;

module.exports = HD;
