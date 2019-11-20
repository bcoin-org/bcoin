/*!
 * x448.js - x448 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Mont = require('./internal/mont');
const ed448 = require('./ed448');

/*
 * Expose
 */

module.exports = new Mont('X448', 446, 56, '2b656f', ed448);
