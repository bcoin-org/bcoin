/*!
 * p192.js - ECDSA-P192 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');

/*
 * Expose
 */

module.exports = new ECDSA('P192');
