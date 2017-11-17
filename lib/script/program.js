/*!
 * program.js - program object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const common = require('./common');
const scriptTypes = common.types;

/**
 * Witness Program
 * @alias module:script.Program
 * @property {Number} version - Ranges from 0 to 16.
 * @property {String|null} type - Null if malformed.
 * @property {Buffer} data - The hash (for now).
 */

class Program {
  /**
   * Create a witness program.
   * @constructor
   * @param {Number} version
   * @param {Buffer} data
   */

  constructor(version, data) {
    assert((version & 0xff) === version);
    assert(version >= 0 && version <= 16);
    assert(Buffer.isBuffer(data));
    assert(data.length >= 2 && data.length <= 40);

    this.version = version;
    this.data = data;
  }

  /**
   * Get the witness program type.
   * @returns {ScriptType}
   */

  getType() {
    if (this.version === 0) {
      if (this.data.length === 20)
        return scriptTypes.WITNESSPUBKEYHASH;

      if (this.data.length === 32)
        return scriptTypes.WITNESSSCRIPTHASH;

      // Fail on bad version=0
      return scriptTypes.WITNESSMALFORMED;
    }

    // No interpretation of script (anyone can spend)
    return scriptTypes.NONSTANDARD;
  }

  /**
   * Test whether the program is either
   * an unknown version or malformed.
   * @returns {Boolean}
   */

  isUnknown() {
    const type = this.getType();
    return type === scriptTypes.WITNESSMALFORMED
      || type === scriptTypes.NONSTANDARD;
  }

  /**
   * Test whether the program is malformed.
   * @returns {Boolean}
   */

  isMalformed() {
    return this.getType() === scriptTypes.WITNESSMALFORMED;
  }

  /**
   * Inspect the program.
   * @returns {String}
   */

  inspect() {
    const data = this.data.toString('hex');
    const type = common.typesByVal[this.getType()].toLowerCase();
    return `<Program: version=${this.version} data=${data} type=${type}>`;
  }
}

/*
 * Expose
 */

module.exports = Program;
