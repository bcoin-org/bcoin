/*!
 * x25519.js - x25519 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Curve25519
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748#section-5
 */

'use strict';

const ECDH = require('./ecdh');
const pre = require('./precomputed/ed25519.json');

/*
 * Expose
 */

module.exports = new ECDH('X25519', 'ED25519', pre);
