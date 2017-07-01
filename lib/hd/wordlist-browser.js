/*!
 * wordlist.js - wordlists for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const words = require('./words');

exports.get = function get(name) {
  switch (name) {
    case 'simplified chinese':
      return words.chinese.simplified;
    case 'traditional chinese':
      return words.chinese.traditional;
    case 'english':
      return words.english;
    case 'french':
      return words.french;
    case 'italian':
      return words.italian;
    case 'japanese':
      return words.japanese;
    case 'spanish':
      return words.spanish;
    default:
      throw new Error(`Unknown language: ${name}.`);
  }
};
