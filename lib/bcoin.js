/**
 * bcoin - javascript bitcoin library
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var Environment = require('./bcoin/env');

module.exports = function BCoin(options) {
  return new Environment(options);
};
