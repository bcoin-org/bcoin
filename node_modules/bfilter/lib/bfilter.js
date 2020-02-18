/*!
 * bfilter.js - bloom filters for javascript
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const BloomFilter = require('./bloom');
const RollingFilter = require('./rolling');

exports.BloomFilter = BloomFilter;
exports.RollingFilter = RollingFilter;
