/*!
 * scripterror.js - script error for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * Script Error
 * An error thrown from the scripting system,
 * potentially pertaining to Script execution.
 * @alias module:script.ScriptError
 * @extends Error
 * @property {String} message - Error message.
 * @property {String} code - Original code passed in.
 * @property {Number} op - Opcode.
 * @property {Number} ip - Instruction pointer.
 */

class ScriptError extends Error {
  /**
   * Create an error.
   * @constructor
   * @param {String} code - Error code.
   * @param {Opcode} op - Opcode.
   * @param {Number?} ip - Instruction pointer.
   */

  constructor(code, op, ip) {
    super();

    this.type = 'ScriptError';
    this.code = code;
    this.message = code;
    this.op = -1;
    this.ip = -1;

    if (typeof op === 'string') {
      this.message = op;
    } else if (op) {
      this.message = `${code} (op=${op.toSymbol()}, ip=${ip})`;
      this.op = op.value;
      this.ip = ip;
    }

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, ScriptError);
  }
}

/*
 * Expose
 */

module.exports = ScriptError;
