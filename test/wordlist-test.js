/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const wordlistBrowser = require('../lib/hd/wordlist-browser');
const words = require('../lib/hd/words');

describe('wordlist-browser', function() {
  it('should return the appropriate wordlist', () => {
    // Check that the wordlist is the same as the one in words.js
    assert.strictEqual(wordlistBrowser.get('simplified chinese'), words.chinese.simplified);
    assert.strictEqual(wordlistBrowser.get('traditional chinese'), words.chinese.traditional);
    assert.strictEqual(wordlistBrowser.get('english'), words.english);
    assert.strictEqual(wordlistBrowser.get('french'), words.french);
    assert.strictEqual(wordlistBrowser.get('italian'), words.italian);
    assert.strictEqual(wordlistBrowser.get('japanese'), words.japanese);
    assert.strictEqual(wordlistBrowser.get('spanish'), words.spanish);

    // expect error when language is not found
    assert.throws(() => {
      wordlistBrowser.get('not a language');
    }, Error, 'Unknown language: not a language.');
  });
});
