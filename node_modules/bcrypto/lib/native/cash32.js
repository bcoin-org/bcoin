/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {cash32} = require('./binding');

/*
 * Cash32
 */

cash32.decode = function decode(str, defaultPrefix = 'bitcoincash') {
  return cash32._decode(str, defaultPrefix);
};

cash32.test = function test(str, defaultPrefix = 'bitcoincash') {
  return cash32._test(str, defaultPrefix);
};

cash32.native = 2;

/*
 * Expose
 */

module.exports = cash32;
