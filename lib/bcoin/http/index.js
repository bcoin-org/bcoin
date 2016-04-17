/*!
 * http/index.js - http for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {
  bcoin.http = {};

  bcoin.http.request = require('./request');
  bcoin.http.client = require('./client')(bcoin);
  bcoin.http.provider = require('./provider')(bcoin);

  if (!bcoin.isBrowser) {
    bcoin.http.base = require('./ba' + 'se');
    bcoin.http.server = require('./ser' + 'ver')(bcoin);
  }

  return bcoin.http;
};
