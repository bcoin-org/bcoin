/*!
 * p521.js - ECDSA-P521 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA512 = require('../sha512');
const SHAKE256 = require('../shake256');

/*
 * Expose
 */

module.exports = new ECDSA('P521', SHA512, SHAKE256);
