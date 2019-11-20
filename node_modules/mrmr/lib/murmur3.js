/*!
 * murmur3.js - murmur3 hash for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

try {
  module.exports = require('./binding').murmur3;
} catch (e) {
  module.exports = require('./murmur3-browser');
}
