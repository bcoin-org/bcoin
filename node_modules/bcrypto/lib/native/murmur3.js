/*!
 * murmur3.js - murmur3 hash for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {murmur3} = require('./binding');

murmur3.native = 2;

module.exports = murmur3;
