/*!
 * errors.js - error objects for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var constants = require('../protocol/constants');
var Amount = require('./amount');

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

  this.type = 'VerifyError';

  this.hash = msg.hash();
  this.height = msg.height;

  if (msg.getCoinbaseHeight && this.height === -1)
    this.height = msg.getCoinbaseHeight();

  if (score == null)
    score = -1;

  this.code = code;
  this.reason = score === -1 ? null : reason;
  this.score = score;
  this.malleated = false;
  this.message = 'Verification failure: '
    + reason
    + ' (code=' + code
    + ', score=' + score
    + ', height=' + this.height
    + ', hash=' + util.revHex(this.hash.toString('hex')) + ')';
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

/**
 * An error thrown from the scripting system,
 * potentially pertaining to Script execution.
 * @exports ScriptError
 * @constructor
 * @extends Error
 * @param {String} code - Error code.
 * @param {(Number|String)?} op - Opcode.
 * @param {Number?} ip - Instruction pointer.
 * @property {String} message - Error message.
 * @property {String} code - Original code passed in.
 * @property {String?} op - Symbolic opcode.
 * @property {Number?} ip - Instruction pointer.
 */

function ScriptError(code, op, ip) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, ScriptError);

  this.type = 'ScriptError';
  this.code = code;

  if (typeof op !== 'string') {
    if (op || ip != null) {
      code += ' (';
      if (op) {
        op = constants.opcodesByVal[op] || op;
        code += 'op=' + op;
        if (ip != null)
          code += ', ';
      }
      if (ip != null)
        code += 'ip=' + ip;
      code += ')';
    }

    this.message = code;
    this.op = op || '';
    this.ip = ip != null ? ip : -1;
  } else {
    this.message = op;
    this.op = '';
    this.ip = -1;
  }
}

util.inherits(ScriptError, Error);

/**
 * An error thrown from the coin selector.
 * @exports FundingError
 * @constructor
 * @extends Error
 * @param {String} msg
 * @param {Amount} available
 * @param {Amount} required
 * @property {String} message - Error message.
 * @property {Amount} availableFunds
 * @property {Amount} requiredFunds
 */

function FundingError(msg, available, required) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, FundingError);

  msg += ' (available=' + Amount.btc(available) + ',';
  msg += ' required=' + Amount.btc(required) + ')';

  this.type = 'FundingError';
  this.message = msg;
  this.availableFunds = available;
  this.requiredFunds = required;
}

util.inherits(FundingError, Error);

/*
 * Expose
 */

exports.VerifyError = VerifyError;
exports.VerifyResult = VerifyResult;
exports.ScriptError = ScriptError;
exports.FundingError = FundingError;
