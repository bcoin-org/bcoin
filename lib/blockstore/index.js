/*!
 * blockstore/index.js - bitcoin blockstore for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module blockstore
 */

exports.AbstractBlockStore = require('./abstract');
exports.FileBlockStore = require('./file');
exports.LevelBlockStore = require('./level');
