/*!
 * mnemonic.js - hd mnemonics for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const cleanse = require('../crypto/cleanse');
const random = require('../crypto/random');
const pbkdf2 = require('../crypto/pbkdf2');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');
const encoding = require('../utils/encoding');
const wordlist = require('./wordlist');
const common = require('./common');
const nfkd = require('../utils/nfkd');

/**
 * HD Mnemonic
 * @alias module:hd.Mnemonic
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

  this.bits = common.MIN_ENTROPY;
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
  'japanese',
  'spanish'
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
    assert(util.isNumber(options.bits));
    assert(options.bits >= common.MIN_ENTROPY);
    assert(options.bits <= common.MAX_ENTROPY);
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
 * Destroy the mnemonic (zeroes entropy).
 */

Mnemonic.prototype.destroy = function destroy() {
  this.bits = common.MIN_ENTROPY;
  this.language = 'english';
  if (this.entropy) {
    cleanse(this.entropy);
    this.entropy = null;
  }
  this.phrase = null;
  this.passphrase = '';
};

/**
 * Generate the seed.
 * @param {String?} passphrase
 * @returns {Buffer} pbkdf2 seed.
 */

Mnemonic.prototype.toSeed = function toSeed(passphrase) {
  let phrase, passwd;

  if (!passphrase)
    passphrase = this.passphrase;

  this.passphrase = passphrase;

  phrase = nfkd(this.getPhrase());
  passwd = nfkd('mnemonic' + passphrase);

  return pbkdf2.derive(
    Buffer.from(phrase, 'utf8'),
    Buffer.from(passwd, 'utf8'),
    2048, 64, 'sha512');
};

/**
 * Get or generate entropy.
 * @returns {Buffer}
 */

Mnemonic.prototype.getEntropy = function getEntropy() {
  if (!this.entropy)
    this.entropy = random.randomBytes(this.bits / 8);

  assert(this.bits / 8 === this.entropy.length);

  return this.entropy;
};

/**
 * Generate a mnemonic phrase from chosen language.
 * @returns {String}
 */

Mnemonic.prototype.getPhrase = function getPhrase() {
  let phrase, wordlist, bits, ent, entropy;

  if (this.phrase)
    return this.phrase;

  phrase = [];
  wordlist = Mnemonic.getWordlist(this.language);

  ent = this.getEntropy();
  bits = this.bits;

  // Include the first `ENT / 32` bits
  // of the hash (the checksum).
  bits += bits / 32;

  // Append the hash to the entropy to
  // make things easy when grabbing
  // the checksum bits.
  entropy = Buffer.allocUnsafe(Math.ceil(bits / 8));
  ent.copy(entropy, 0);
  digest.sha256(ent).copy(entropy, ent.length);

  // Build the mnemonic by reading
  // 11 bit indexes from the entropy.
  for (let i = 0; i < bits / 11; i++) {
    let index = 0;
    for (let j = 0; j < 11; j++) {
      let pos = i * 11 + j;
      let bit = pos % 8;
      let oct = (pos - bit) / 8;
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
  let bits, ent, entropy, lang;
  let chk, wordlist, cbits, cbytes, words;

  assert(typeof phrase === 'string');

  words = phrase.split(/[ \u3000]+/);
  bits = words.length * 11;
  cbits = bits % 32;
  cbytes = Math.ceil(cbits / 8);
  bits -= cbits;

  assert(bits >= common.MIN_ENTROPY);
  assert(bits <= common.MAX_ENTROPY);
  assert(bits % 32 === 0);
  assert(cbits !== 0, 'Invalid checksum.');

  ent = Buffer.allocUnsafe(Math.ceil((bits + cbits) / 8));
  ent.fill(0);

  lang = Mnemonic.getLanguage(words[0]);
  wordlist = Mnemonic.getWordlist(lang);

  for (let i = 0; i < words.length; i++) {
    let word = words[i];
    let index = util.binarySearch(wordlist, word, util.strcmp);

    if (index === -1)
      throw new Error('Could not find word.');

    for (let j = 0; j < 11; j++) {
      let pos = i * 11 + j;
      let bit = pos % 8;
      let oct = (pos - bit) / 8;
      let b = (index >>> (10 - j)) & 1;
      ent[oct] |= b << (7 - bit);
    }
  }

  entropy = ent.slice(0, ent.length - cbytes);
  ent = ent.slice(ent.length - cbytes);
  chk = digest.sha256(entropy);

  for (let i = 0; i < cbits; i++) {
    let bit = i % 8;
    let oct = (i - bit) / 8;
    let b = (ent[oct] >>> (7 - bit)) & 1;
    let j = (chk[oct] >>> (7 - bit)) & 1;
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
  assert(entropy.length * 8 >= common.MIN_ENTROPY);
  assert(entropy.length * 8 <= common.MAX_ENTROPY);
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
  let lang, wordlist;

  for (lang of Mnemonic.languages) {
    wordlist = Mnemonic.getWordlist(lang);
    if (util.binarySearch(wordlist, word, util.strcmp) !== -1)
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
  return wordlist.get(language);
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
  assert(util.isNumber(json.bits));
  assert(typeof json.language === 'string');
  assert(typeof json.entropy === 'string');
  assert(typeof json.phrase === 'string');
  assert(typeof json.passphrase === 'string');
  assert(json.bits >= common.MIN_ENTROPY);
  assert(json.bits <= common.MAX_ENTROPY);
  assert(json.bits % 32 === 0);
  assert(json.bits / 8 === json.entropy.length / 2);

  this.bits = json.bits;
  this.language = json.language;
  this.entropy = Buffer.from(json.entropy, 'hex');
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
 * Calculate serialization size.
 * @returns {Number}
 */

Mnemonic.prototype.getSize = function getSize() {
  let size = 0;
  size += 3;
  size += this.getEntropy().length;
  size += encoding.sizeVarString(this.getPhrase(), 'utf8');
  size += encoding.sizeVarString(this.passphrase, 'utf8');
  return size;
};

/**
 * Write the mnemonic to a buffer writer.
 * @params {BufferWriter} bw
 */

Mnemonic.prototype.toWriter = function toWriter(bw) {
  let lang = Mnemonic.languages.indexOf(this.language);

  assert(lang !== -1);

  bw.writeU16(this.bits);
  bw.writeU8(lang);
  bw.writeBytes(this.getEntropy());
  bw.writeVarString(this.getPhrase(), 'utf8');
  bw.writeVarString(this.passphrase, 'utf8');

  return bw;
};

/**
 * Serialize mnemonic.
 * @returns {Buffer}
 */

Mnemonic.prototype.toRaw = function toRaw(writer) {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Mnemonic.prototype.fromReader = function fromReader(br) {
  this.bits = br.readU16();
  this.language = Mnemonic.languages[br.readU8()];
  this.entropy = br.readBytes(this.bits / 8);
  this.phrase = br.readVarString('utf8');
  this.passphrase = br.readVarString('utf8');

  assert(this.language);
  assert(this.bits >= common.MIN_ENTROPY);
  assert(this.bits <= common.MAX_ENTROPY);
  assert(this.bits % 32 === 0);

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Mnemonic.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate mnemonic from buffer reader.
 * @param {BufferReader} br
 * @returns {Mnemonic}
 */

Mnemonic.fromReader = function fromReader(br) {
  return new Mnemonic().fromReader(br);
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
  return `<Mnemonic: ${this.getPhrase()}>`;
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

/*
 * Expose
 */

module.exports = Mnemonic;
