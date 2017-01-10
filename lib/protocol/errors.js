/*!
 * errors.js - error objects for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');

/**
 * An error thrown during verification. Can be either
 * a mempool transaction validation error or a blockchain
 * block verification error. Ultimately used to send
 * `reject` packets to peers.
 * @exports VerifyError
 * @constructor
 * @extends Error
 * @param {Block|TX} msg
 * @param {String} code - Reject packet ccode.
 * @param {String} reason - Reject packet reason.
 * @param {Number} score - Ban score increase
 * (can be -1 for no reject packet).
 * @property {String} code
 * @property {Buffer} hash
 * @property {Number} height (will be the coinbase height if not present).
 * @property {Number} score
 * @property {String} message
 */

function VerifyError(msg, code, reason, score) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, VerifyError);

  assert(typeof code === 'string');
  assert(typeof reason === 'string');
  assert(score >= 0);

  this.type = 'VerifyError';
  this.message = '';
  this.code = code;
  this.reason = reason;
  this.score = score;

  this.hash = msg.hash();
  this.malleated = false;

  this.message = 'Verification failure: ' + reason
    + ' (code=' + code + ', score=' + score
    + ', hash=' + util.revHex(this.hash.toString('hex'))
    + ')';
}

util.inherits(VerifyError, Error);

/**
 * Verication result.
 * @constructor
 */

function VerifyResult() {
  this.reason = 'unknown';
  this.score = 0;
}

/*
 * Expose
 */

exports.VerifyError = VerifyError;
exports.VerifyResult = VerifyResult;
