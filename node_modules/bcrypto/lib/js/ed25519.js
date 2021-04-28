/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/EdDSA#Ed25519
 *   https://ed25519.cr.yp.to/ed25519-20110926.pdf
 *   https://tools.ietf.org/html/rfc8032#section-5.1
 */

'use strict';

const EDDSA = require('./eddsa');
const SHA512 = require('../sha512');
const pre = require('./precomputed/ed25519.json');

/*
 * Expose
 */

module.exports = new EDDSA('ED25519', 'X25519', null, SHA512, pre);
