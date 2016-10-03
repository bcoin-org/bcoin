'use strict';

var utils = require('../utils/utils');

exports.ldb = require('./ldb');

if (utils.isBrowser)
  exports.level = require('./level');

exports.LowlevelUp = require('./lowlevelup');
exports.RBT = require('./rbt');
