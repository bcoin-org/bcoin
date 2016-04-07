/**
 * protocol/index.js - bitcoin protocol for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {
  bcoin.protocol = {};

  bcoin.protocol.constants = require('./constants');
  bcoin.protocol.network = require('./network').get(bcoin.networkType);
  bcoin.protocol.framer = require('./framer')(bcoin);
  bcoin.protocol.parser = require('./parser')(bcoin);

  return bcoin.protocol;
};
