/*!
 * x25519.js - x25519 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Mont = require('./internal/mont');
const ed25519 = require('./ed25519');

/*
 * Expose
 */

module.exports = new Mont('X25519', 253, 32, '2b656e', ed25519);
