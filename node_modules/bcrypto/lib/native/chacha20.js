/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {ChaCha20} = require('./binding');

ChaCha20.native = 2;

/*
 * Expose
 */

module.exports = ChaCha20;
