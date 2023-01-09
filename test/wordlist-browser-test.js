/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const wordlist_browser = require('../lib/hd/wordlist-browser');
const words = require('../lib/hd/words');

describe('wordlist-browser', function() {
  it('should return the appropriate wordlist', () => {
    assert.strictEqual(wordlist_browser.get(`simplified chinese`), words.chinese.simplified);
    assert.strictEqual(wordlist_browser.get(`traditional chinese`), words.chinese.traditional);
    assert.strictEqual(wordlist_browser.get(`english`), words.english);
    assert.strictEqual(wordlist_browser.get(`french`), words.french);
    assert.strictEqual(wordlist_browser.get(`italian`), words.italian);
    assert.strictEqual(wordlist_browser.get(`japanese`), words.japanese);
    assert.strictEqual(wordlist_browser.get(`spanish`), words.spanish);

    // expect error when language is not found
    assert.throws(() => {
      wordlist_browser.get(`not a language`);
    }, Error, `Unknown language: not a language.`);
  });
});
