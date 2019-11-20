/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 *   https://tools.ietf.org/html/rfc8032
 *   https://tools.ietf.org/html/rfc8032#appendix-A
 *   https://tools.ietf.org/html/rfc8032#appendix-B
 */

'use strict';

const EDDSA = require('./eddsa');
const SHA512 = require('../sha512');
const pre = require('./precomputed/ed25519.json');

/*
 * Expose
 */

module.exports = new EDDSA('ED25519', 'X25519', SHA512, pre);
