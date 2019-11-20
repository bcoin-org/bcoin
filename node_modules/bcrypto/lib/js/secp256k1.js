/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA256 = require('../sha256');
const pre = require('./precomputed/secp256k1.json');

/**
 * Secp256k1
 */

class Secp256k1 extends ECDSA {
  constructor() {
    super('SECP256K1', SHA256, pre);
  }

  schnorrSign(msg, key) {
    return this.schnorr.sign(msg, key);
  }

  schnorrVerify(msg, sig, key) {
    return this.schnorr.verify(msg, sig, key);
  }

  schnorrBatchVerify(batch) {
    return this.schnorr.batchVerify(batch);
  }
}

/*
 * Expose
 */

module.exports = new Secp256k1();
