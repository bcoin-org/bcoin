/**
 * Javascript bitcoin library.
 * @module bcoin
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var env = require('./bcoin/env');
var utils = require('./bcoin/utils');
var global = utils.global;

if (utils.isBrowser)
  global.bcoin = exports;

/**
 * Create a new Environment. Note that this will
 * be cached by network. Calling `bcoin('main')`
 * twice will return the same environment.
 * @param {Object} options - See {@link Environment}.
 * @returns {Environment}
 */

function BCoin(options) {
  env.setDefaults(options);
  return BCoin;
}

utils.merge(BCoin, env);

module.exports = BCoin;
