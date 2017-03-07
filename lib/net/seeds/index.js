/*!
 * seeds.js - seeds for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var main = require('./main');
var testnet = require('./testnet');

exports.get = function get(type) {
  switch (type) {
    case 'main':
      return main;
    case 'testnet':
      return testnet;
    default:
      return [];
  }
};
