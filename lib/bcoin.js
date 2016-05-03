/**
 * Javascript bitcoin library.
 * @module bcoin
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var Environment = require('./bcoin/env');
var utils = require('./bcoin/utils');
var global = utils.global;
var env = {};

/**
 * Create a new Environment. Note that this will
 * be cached by network. Calling `bcoin('main')`
 * twice will return the same environment.
 * @param {Object} options - See {@link Environment}.
 * @returns {Environment}
 */

function BCoin(options) {
  var network = 'main';

  if (options) {
    if (options.network)
      network = options.network;
    else if (typeof options === 'string')
      network = options;
  }

  if (!env[network])
    env[network] = new Environment(options);

  return env[network];
}

BCoin.env = Environment;
BCoin.utils = utils;

if (utils.isBrowser)
  global.bcoin = BCoin;

module.exports = BCoin;
