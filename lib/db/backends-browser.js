/**
 * backends-browser.js - database backends for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var level = require('./level');
var RBT = require('./rbt');

exports.get = function get(name) {
  if (name === 'rbt')
    return RBT;
  return level;
};
