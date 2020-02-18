/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Poly1305} = require('./binding');

Poly1305.native = 2;

module.exports = Poly1305;
