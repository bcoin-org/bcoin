'use strict';

var utils = require('../utils/utils');
var lazy = require('../utils/lazy')(require, exports);

lazy('ldb', './ldb');

if (utils.isBrowser)
  lazy('level', './level');

lazy('LowlevelUp', './lowlevelup');
lazy('RBT', './rbt');
