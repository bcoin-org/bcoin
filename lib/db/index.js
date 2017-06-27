/*!
 * db/index.js - data management for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module db
 */

exports.backends = require('./backends');
exports.LDB = require('./ldb');
exports.LowlevelUp = require('./lowlevelup');
exports.MemDB = require('./memdb');
