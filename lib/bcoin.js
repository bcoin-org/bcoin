/**
 * Javascript bitcoin library.
 * @module bcoin
 * @license
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var Environment = require('./bcoin/env');
var networks = {};

/**
 * Create a new Environment. Note that this will
 * be cached by network. Calling `bcoin('main')`
 * twice will return the same environment.
 * @param {Object} options - See {@link Environment}.
 * @returns {Environment}
 */

module.exports = function BCoin(options) {
  var network = 'main';

  if (options) {
    if (options.network)
      network = options.network;
    else if (typeof options === 'string')
      network = options;
  }

  if (!networks[network])
    networks[network] = new Environment(options);

  return networks[network];
};

module.exports.env = Environment;
