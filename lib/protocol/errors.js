/*!
 * errors.js - error objects for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module protocol/errors
 */

const assert = require('assert');

/**
 * Verify Error
 * An error thrown during verification. Can be either
 * a mempool transaction validation error or a blockchain
 * block verification error. Ultimately used to send
 * `reject` packets to peers.
 * @extends Error
 * @param {Block|TX} msg
 * @param {String} code - Reject packet code.
 * @param {String} reason - Reject packet reason.
 * @param {Number} score - Ban score increase
 * (can be -1 for no reject packet).
 * @param {Boolean} malleated
 */

class VerifyError extends Error {
  /**
   * Create a verify error.
   * @constructor
   * @param {Block|TX} msg
   * @param {String} code - Reject packet code.
   * @param {String} reason - Reject packet reason.
   * @param {Number} score - Ban score increase
   * (can be -1 for no reject packet).
   * @param {Boolean} malleated
   */

  constructor(msg, code, reason, score, malleated) {
    super();

    assert(typeof code === 'string');
    assert(typeof reason === 'string');
    assert(score >= 0);

    this.type = 'VerifyError';
    this.message = '';
    this.code = code;
    this.reason = reason;
    this.score = score;
    this.hash = msg.hash('hex');
    this.malleated = malleated || false;

    this.message = `Verification failure: ${reason}`
      + ` (code=${code} score=${score} hash=${msg.rhash()})`;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, VerifyError);
  }
}

/*
 * Expose
 */

exports.VerifyError = VerifyError;
