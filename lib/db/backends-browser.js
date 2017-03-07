/**
 * backends-browser.js - database backends for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var level = require('./level');
var MemDB = require('./memdb');

exports.get = function get(name) {
  if (name === 'memory')
    return MemDB;
  return level;
};
