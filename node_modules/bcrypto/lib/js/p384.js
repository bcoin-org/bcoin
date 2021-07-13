/*!
 * p384.js - ECDSA-P384 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA384 = require('../sha384');

/*
 * Expose
 */

module.exports = new ECDSA('P384', SHA384, SHA384);
