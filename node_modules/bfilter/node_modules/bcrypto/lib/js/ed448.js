/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://eprint.iacr.org/2015/625.pdf
 *   https://tools.ietf.org/html/rfc8032#section-5.2
 */

'use strict';

const EDDSA = require('./eddsa');
const SHAKE256 = require('../shake256');

/*
 * Expose
 */

module.exports = new EDDSA('ED448', 'X448', 'MONT448', SHAKE256);
