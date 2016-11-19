/*!
 * program.js - program object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var util = require('../utils/util');
var assert = require('assert');
var scriptTypes = constants.scriptTypes;

/**
 * Witness Program
 * @constructor
 * @param {Number} version
 * @param {Buffer} data
 * @property {Number} version - Ranges from 0 to 16.
 * @property {String|null} type - Null if malformed. `unknown` if unknown
 * version (treated as anyone-can-spend). Otherwise one of `witnesspubkeyhash`
 * or `witnessscripthash`.
 * @property {Buffer} data - The hash (for now).
 */

function Program(version, data) {
  if (!(this instanceof Program))
    return new Program(version, data);

  assert(util.isNumber(version));
  assert(Buffer.isBuffer(data));
  assert(version >= 0 && version <= 16);
  assert(data.length >= 2 && data.length <= 40);

  this.version = version;
  this.data = data;
}

/**
 * Get the witness program type.
 * @returns {ScriptType}
 */

Program.prototype.getType = function getType() {
  if (this.version === 0) {
    if (this.data.length === 20)
      return scriptTypes.WITNESSPUBKEYHASH;

    if (this.data.length === 32)
      return scriptTypes.WITNESSSCRIPTHASH;

    // Fail on bad version=0
    return scriptTypes.WITNESSMALFORMED;
  }

  if (this.version === 1) {
    if (this.data.length === 32)
      return scriptTypes.WITNESSMASTHASH;

    // Fail on bad version=1
    return scriptTypes.WITNESSMALFORMED;
  }

  // No interpretation of script (anyone can spend)
  return scriptTypes.NONSTANDARD;
};

/**
 * Test whether the program is either
 * an unknown version or malformed.
 * @returns {Boolean}
 */

Program.prototype.isUnknown = function isUnknown() {
  var type = this.getType();
  return type === scriptTypes.WITNESSMALFORMED
    || type === scriptTypes.NONSTANDARD;
};

/**
 * Test whether the program is malformed.
 * @returns {Boolean}
 */

Program.prototype.isMalformed = function isMalformed() {
  return this.getType() === scriptTypes.WITNESSMALFORMED;
};

/**
 * Inspect the program.
 * @returns {String}
 */

Program.prototype.inspect = function inspect() {
  return '<Program:'
    + ' version=' + this.version
    + ' data=' + this.data.toString('hex')
    + ' type=' + constants.scriptTypesByVal[this.getType()].toLowerCase()
    + '>';
};

/*
 * Expose
 */

module.exports = Program;
