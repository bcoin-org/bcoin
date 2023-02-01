/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const {MIN_ENTROPY} = require('../lib/hd/common');

const tests = {
  english: require('./data/mnemonic-english.json'),
  japanese: require('./data/mnemonic-japanese.json')
};

const LANGUAGE_ENGLISH = 'english';

describe('Mnemonic', function() {
  for (const language of Object.keys(tests)) {
    const test = tests[language];
    let i = 0;

    for (const data of test) {
      const entropy = Buffer.from(data[0], 'hex');
      const phrase = data[1];
      const passphrase = data[2];
      const seed = Buffer.from(data[3], 'hex');
      const xpriv = data[4];

      it(`should create a ${language} mnemonic from entropy (${i})`, () => {
        const mnemonic = new Mnemonic({
          language,
          entropy
        });

        assert.strictEqual(mnemonic.getPhrase(), phrase);
        assert.bufferEqual(mnemonic.getEntropy(), entropy);
        assert.bufferEqual(mnemonic.toSeed(passphrase), seed);

        const key = HDPrivateKey.fromMnemonic(mnemonic, passphrase);
        assert.strictEqual(key.toBase58('main'), xpriv);
      });

      it(`should create a ${language} mnemonic from phrase (${i})`, () => {
        const mnemonic = new Mnemonic({
          language,
          phrase
        });

        assert.strictEqual(mnemonic.getPhrase(), phrase);
        assert.bufferEqual(mnemonic.getEntropy(), entropy);
        assert.bufferEqual(mnemonic.toSeed(passphrase), seed);

        const key = HDPrivateKey.fromMnemonic(mnemonic, passphrase);
        assert.strictEqual(key.toBase58('main'), xpriv);
      });

      i += 1;
    }
  }

  it('should verify phrase', () => {
    const m1 = new Mnemonic();
    const m2 = Mnemonic.fromPhrase(m1.getPhrase());
    assert.bufferEqual(m2.getEntropy(), m1.getEntropy());
    assert.strictEqual(m2.bits, m1.bits);
    assert.strictEqual(m2.language, m1.language);
    assert.bufferEqual(m2.toSeed(), m1.toSeed());
  });

  it('should return true for isMnemonic when passed a Mnemonic object', () => {
    const m1 = new Mnemonic();
    assert.strictEqual(Mnemonic.isMnemonic(m1), true);
  });

  it('should return false for isMnemonic when passed a string', () => {
    const m1 = new Mnemonic();
    assert.strictEqual(Mnemonic.isMnemonic(m1.getPhrase()), false);
  });

  it('should return the phrase from toString', () => {
    const m1 = new Mnemonic();
    assert.strictEqual(m1.phrase, null);
    assert.strictEqual(m1.entropy, null);
    const phrase = m1.getPhrase();
    assert.notStrictEqual(m1.phrase, null);
    assert.notStrictEqual(m1.entropy, null);
    assert.strictEqual(m1.toString(), phrase);
  });

  it('should handle fromRaw correctly', () => {
    const m1 = new Mnemonic();
    const m2 = Mnemonic.fromRaw(m1.toRaw());
    assert.strictEqual(m1.getPhrase(), m2.getPhrase());
  });

  it('should handle fromJSON correctly', () => {
    const m1 = new Mnemonic();

    const json = m1.toJSON();
    assert.strictEqual(typeof json, 'object');
    assert.strictEqual(json.entropy, m1.entropy.toString('hex'));
    assert.strictEqual(json.phrase, m1.phrase);

    const m2 = Mnemonic.fromJSON(json);
    assert.strictEqual(m1.getPhrase(), m2.getPhrase());
    assert.strictEqual(m1.language, m2.language);
    assert.strictEqual(m1.bits, m2.bits);
    assert.bufferEqual(m1.getEntropy(), m2.getEntropy());
  });

  it('should expect an error from getLanguage() when word is not in any language wordlist', () => {
    assert.throws(() => {
        Mnemonic.getLanguage('notaword');
      },
      Error,
      'Unknown word: notaword');
  });

  it('should handle fromEntropy correctly', () => {
    const m1 = new Mnemonic();
    const m2 = Mnemonic.fromEntropy(m1.getEntropy(), LANGUAGE_ENGLISH);
    assert.strictEqual(m1.getPhrase(), m2.getPhrase());
    assert.strictEqual(LANGUAGE_ENGLISH, m2.language);
    assert.strictEqual(m1.bits, m2.bits);
    assert.bufferEqual(m1.getEntropy(), m2.getEntropy());
  });

  it('should expect an error from fromPhrase() when phrase contains a word not in the wordlist', () => {
    const m1 = new Mnemonic();
    const phrase = m1.getPhrase();
    const phraseArray = phrase.split(' ');
    phraseArray[1] = 'notaword';
    const phraseWithBadWord = phraseArray.join(' ');

    assert.throws(() => {
        Mnemonic.fromPhrase(phraseWithBadWord);
      },
      Error,
      'Unknown word: notaword');
  });

  it('should expect an error from fromPhrase() when phrase array is missing a word (for some reason)', () => {
    const m1 = new Mnemonic();
    const phrase = m1.getPhrase();
    const phraseArray = phrase.split(' ');
    phraseArray.pop();
    const phraseWithMissingWord = phraseArray.join(' ');

    assert.throws(() => {
        Mnemonic.fromPhrase(phraseWithMissingWord);
      },
      Error,
      'Invalid checksum');
  });

  it('should handle destroy correctly', () => {
    const m1 = new Mnemonic();
    m1.destroy();
    assert.strictEqual(m1.phrase, null);
    assert.strictEqual(m1.language, LANGUAGE_ENGLISH);
    assert.strictEqual(m1.bits, MIN_ENTROPY);
    assert.strictEqual(m1.entropy, null);
  });

  it('should handle destroy correctly when entropy is set', () => {
    const m1 = new Mnemonic();
    m1.entropy = Buffer.from('00000000000000000000000000000000', 'hex');
    m1.destroy();
    assert.strictEqual(m1.phrase, null);
    assert.strictEqual(m1.language, LANGUAGE_ENGLISH);
    assert.strictEqual(m1.bits, MIN_ENTROPY);
    assert.strictEqual(m1.entropy, null);
  });

  it('should handle fromOptions correctly when a phrase is passed in', () => {
    const m1 = new Mnemonic();
    const m2 = Mnemonic.fromOptions(m1.getPhrase().toString());

    assert.strictEqual(m1.phrase, m2.phrase);
    assert.strictEqual(LANGUAGE_ENGLISH, m2.language);
    assert.strictEqual(256, m2.bits);
    assert.strictEqual(32, m2.entropy.length);
  });

  it('should handle fromOption correctly when options.entropy is set', () => {
    const entropy = Buffer.from('00000000000000000000000000000000', 'hex');
    const m2 = Mnemonic.fromOptions({ entropy: entropy});

    assert.strictEqual(null, m2.phrase);
    assert.strictEqual(LANGUAGE_ENGLISH, m2.language);
    assert.strictEqual(128, m2.bits);
    assert.strictEqual(16, m2.entropy.length);
  });

  it('should handle fromOption correctly when no options are set', () => {
    const m2 = Mnemonic.fromOptions({ });

    assert.strictEqual(null, m2.phrase);
    assert.strictEqual(LANGUAGE_ENGLISH, m2.language);
    assert.strictEqual(256, m2.bits);
    assert.strictEqual(null, m2.entropy);
  });
});
