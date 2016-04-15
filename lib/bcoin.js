/**
 * Javascript bitcoin library.
 * @module bcoin
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var Environment = require('./bcoin/env');

/**
 * Create a new Environment.
 * @param {Object} options - See {@link Environment}.
 * @returns {Environment}
 */

module.exports = function BCoin(options) {
  return new Environment(options);
};
