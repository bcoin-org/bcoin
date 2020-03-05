/*!
 * salsa20.js - salsa20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Salsa20} = require('./binding');

Salsa20.native = 2;

/*
 * Expose
 */

module.exports = Salsa20;
