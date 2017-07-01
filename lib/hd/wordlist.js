/*!
 * wordlist.js - wordlists for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.get = function get(name) {
  switch (name) {
    case 'simplified chinese':
      return require('./words/chinese-simplified.js');
    case 'traditional chinese':
      return require('./words/chinese-traditional.js');
    case 'english':
      return require('./words/english.js');
    case 'french':
      return require('./words/french.js');
    case 'italian':
      return require('./words/italian.js');
    case 'japanese':
      return require('./words/japanese.js');
    case 'spanish':
      return require('./words/spanish.js');
    default:
      throw new Error(`Unknown language: ${name}.`);
  }
};
