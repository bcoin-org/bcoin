/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA256 = require('../sha256');
const pre = require('./precomputed/secp256k1.json');

/*
 * Expose
 */

module.exports = new ECDSA('SECP256K1', SHA256, SHA256, pre);
