/*!
 * mnemonic.js - hd mnemonics for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const sha256 = require('bcrypto/lib/sha256');
const cleanse = require('bcrypto/lib/cleanse');
const random = require('bcrypto/lib/random');
const pbkdf2 = require('bcrypto/lib/pbkdf2');
const sha512 = require('bcrypto/lib/sha512');
const wordlist = require('./wordlist');
const common = require('./common');
const nfkd = require('./nfkd');

/*
 * Constants
 */

const wordlistCache = Object.create(null);

/**
 * HD Mnemonic
 * @alias module:hd.Mnemonic
 */

class Mnemonic {
  /**
   * Create a mnemonic.
   * @constructor
   * @param {Object} options
   * @param {Number?} options.bit - Bits of entropy (Must
   * be a multiple of 8) (default=128).
   * @param {Buffer?} options.entropy - Entropy bytes. Will
   * be generated with `options.bits` bits of entropy
   * if not present.
   * @param {String?} options.phrase - Mnemonic phrase (will
   * be generated if not present).
   * @param {String?} options.language - Language.
   */

  constructor(options) {
    this.bits = common.MIN_ENTROPY;
    this.language = 'english';
    this.entropy = null;
    this.phrase = null;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    if (typeof options === 'string')
      options = { phrase: options };

    if (options.bits != null) {
      assert((options.bits & 0xffff) === options.bits);
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

    if (options.phrase) {
      this.fromPhrase(options.phrase);
      return this;
    }

    if (options.entropy) {
      this.fromEntropy(options.entropy);
      return this;
    }

    return this;
  }

  /**
   * Instantiate mnemonic from options.
   * @param {Object} options
   * @returns {Mnemonic}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Destroy the mnemonic (zeroes entropy).
   */

  destroy() {
    this.bits = common.MIN_ENTROPY;
    this.language = 'english';
    if (this.entropy) {
      cleanse(this.entropy);
      this.entropy = null;
    }
    this.phrase = null;
  }

  /**
   * Generate the seed.
   * @param {String?} passphrase
   * @returns {Buffer} pbkdf2 seed.
   */

  toSeed(passphrase) {
    if (!passphrase)
      passphrase = '';

    const phrase = nfkd(this.getPhrase());
    const passwd = nfkd(`mnemonic${passphrase}`);

    return pbkdf2.derive(sha512,
      Buffer.from(phrase, 'utf8'),
      Buffer.from(passwd, 'utf8'),
      2048, 64);
  }

  /**
   * Get or generate entropy.
   * @returns {Buffer}
   */

  getEntropy() {
    if (!this.entropy)
      this.entropy = random.randomBytes(this.bits / 8);

    assert(this.bits / 8 === this.entropy.length);

    return this.entropy;
  }

  /**
   * Generate a mnemonic phrase from chosen language.
   * @returns {String}
   */

  getPhrase() {
    if (this.phrase)
      return this.phrase;

    // Include the first `ENT / 32` bits
    // of the hash (the checksum).
    const wbits = this.bits + (this.bits / 32);

    // Get entropy and checksum.
    const entropy = this.getEntropy();
    const chk = sha256.digest(entropy);

    // Append the hash to the entropy to
    // make things easy when grabbing
    // the checksum bits.
    const size = Math.ceil(wbits / 8);
    const data = Buffer.allocUnsafe(size);
    entropy.copy(data, 0);
    chk.copy(data, entropy.length);

    // Build the mnemonic by reading
    // 11 bit indexes from the entropy.
    const list = Mnemonic.getWordlist(this.language);

    let phrase = [];
    for (let i = 0; i < wbits / 11; i++) {
      let index = 0;
      for (let j = 0; j < 11; j++) {
        const pos = i * 11 + j;
        const bit = pos % 8;
        const oct = (pos - bit) / 8;
        index <<= 1;
        index |= (data[oct] >>> (7 - bit)) & 1;
      }
      phrase.push(list.words[index]);
    }

    // Japanese likes double-width spaces.
    if (this.language === 'japanese')
      phrase = phrase.join('\u3000');
    else
      phrase = phrase.join(' ');

    this.phrase = phrase;

    return phrase;
  }

  /**
   * Inject properties from phrase.
   * @private
   * @param {String} phrase
   */

  fromPhrase(phrase) {
    assert(typeof phrase === 'string');
    assert(phrase.length <= 1000);

    const words = phrase.trim().split(/[\s\u3000]+/);
    const wbits = words.length * 11;
    const cbits = wbits % 32;

    assert(cbits !== 0, 'Invalid checksum.');

    const bits = wbits - cbits;

    assert(bits >= common.MIN_ENTROPY);
    assert(bits <= common.MAX_ENTROPY);
    assert(bits % 32 === 0);

    const size = Math.ceil(wbits / 8);
    const data = Buffer.allocUnsafe(size);
    data.fill(0);

    const lang = Mnemonic.getLanguage(words[0]);
    const list = Mnemonic.getWordlist(lang);

    // Rebuild entropy bytes.
    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      const index = list.map[word];

      if (index == null)
        throw new Error('Could not find word.');

      for (let j = 0; j < 11; j++) {
        const pos = i * 11 + j;
        const bit = pos % 8;
        const oct = (pos - bit) / 8;
        const val = (index >>> (10 - j)) & 1;
        data[oct] |= val << (7 - bit);
      }
    }

    const cbytes = Math.ceil(cbits / 8);
    const entropy = data.slice(0, data.length - cbytes);
    const chk1 = data.slice(data.length - cbytes);
    const chk2 = sha256.digest(entropy);

    // Verify checksum.
    for (let i = 0; i < cbits; i++) {
      const bit = i % 8;
      const oct = (i - bit) / 8;
      const b1 = (chk1[oct] >>> (7 - bit)) & 1;
      const b2 = (chk2[oct] >>> (7 - bit)) & 1;
      if (b1 !== b2)
        throw new Error('Invalid checksum.');
    }

    assert(bits / 8 === entropy.length);

    this.bits = bits;
    this.language = lang;
    this.entropy = entropy;
    this.phrase = phrase;

    return this;
  }

  /**
   * Instantiate mnemonic from a phrase (validates checksum).
   * @param {String} phrase
   * @returns {Mnemonic}
   * @throws on bad checksum
   */

  static fromPhrase(phrase) {
    return new this().fromPhrase(phrase);
  }

  /**
   * Inject properties from entropy.
   * @private
   * @param {Buffer} entropy
   * @param {String?} lang
   */

  fromEntropy(entropy, lang) {
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
  }

  /**
   * Instantiate mnemonic from entropy.
   * @param {Buffer} entropy
   * @param {String?} lang
   * @returns {Mnemonic}
   */

  static fromEntropy(entropy, lang) {
    return new this().fromEntropy(entropy, lang);
  }

  /**
   * Determine a single word's language.
   * @param {String} word
   * @returns {String} Language.
   * @throws on not found.
   */

  static getLanguage(word) {
    for (const lang of Mnemonic.languages) {
      const list = Mnemonic.getWordlist(lang);
      if (list.map[word] != null)
        return lang;
    }

    throw new Error('Could not determine language.');
  }

  /**
   * Retrieve the wordlist for a language.
   * @param {String} lang
   * @returns {Object}
   */

  static getWordlist(lang) {
    const cache = wordlistCache[lang];

    if (cache)
      return cache;

    const words = wordlist.get(lang);
    const list = new WordList(words);

    wordlistCache[lang] = list;

    return list;
  }

  /**
   * Convert mnemonic to a json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      bits: this.bits,
      language: this.language,
      entropy: this.getEntropy().toString('hex'),
      phrase: this.getPhrase()
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json);
    assert((json.bits & 0xffff) === json.bits);
    assert(typeof json.language === 'string');
    assert(typeof json.entropy === 'string');
    assert(typeof json.phrase === 'string');
    assert(json.bits >= common.MIN_ENTROPY);
    assert(json.bits <= common.MAX_ENTROPY);
    assert(json.bits % 32 === 0);
    assert(json.bits / 8 === json.entropy.length / 2);

    this.bits = json.bits;
    this.language = json.language;
    this.entropy = Buffer.from(json.entropy, 'hex');
    this.phrase = json.phrase;

    return this;
  }

  /**
   * Instantiate mnemonic from json object.
   * @param {Object} json
   * @returns {Mnemonic}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 3;
    size += this.getEntropy().length;
    return size;
  }

  /**
   * Write the mnemonic to a buffer writer.
   * @params {BufferWriter} bw
   */

  toWriter(bw) {
    const lang = Mnemonic.languages.indexOf(this.language);

    assert(lang !== -1);

    bw.writeU16(this.bits);
    bw.writeU8(lang);
    bw.writeBytes(this.getEntropy());

    return bw;
  }

  /**
   * Serialize mnemonic.
   * @returns {Buffer}
   */

  toRaw(writer) {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    const bits = br.readU16();

    assert(bits >= common.MIN_ENTROPY);
    assert(bits <= common.MAX_ENTROPY);
    assert(bits % 32 === 0);

    const language = Mnemonic.languages[br.readU8()];
    assert(language);

    this.bits = bits;
    this.language = language;
    this.entropy = br.readBytes(bits / 8);

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate mnemonic from buffer reader.
   * @param {BufferReader} br
   * @returns {Mnemonic}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate mnemonic from serialized data.
   * @param {Buffer} data
   * @returns {Mnemonic}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Convert the mnemonic to a string.
   * @returns {String}
   */

  toString() {
    return this.getPhrase();
  }

  /**
   * Inspect the mnemonic.
   * @returns {String}
   */

  inspect() {
    return `<Mnemonic: ${this.getPhrase()}>`;
  }

  /**
   * Test whether an object is a Mnemonic.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isMnemonic(obj) {
    return obj instanceof Mnemonic;
  }
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
 * Word List
 * @ignore
 */

class WordList {
  /**
   * Create word list.
   * @constructor
   * @ignore
   * @param {Array} words
   */

  constructor(words) {
    this.words = words;
    this.map = Object.create(null);

    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      this.map[word] = i;
    }
  }
}

/*
 * Expose
 */

module.exports = Mnemonic;
