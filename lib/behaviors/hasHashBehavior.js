'use strict';

const hash256 = require('bcrypto/lib/hash256');
const util = require('../utils/util');

class HasHashBehavior {

  constructor() {
    this._hash = null;
    this._hhash = null;
    this._rhash = null;
    this._whash = null;
  }

   /**
   * Clear any cached values (abstract).
   */

  _refresh() {
    this._hash = null;
    this._hhash = null;
    this._rhash = null;
    this._whash = null;
  }

  /**
   * Clear any cached values.
   */

  refresh() {
    return this._refresh();
  }

  /**
   * Get little-endian block hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash());
  }

  /**
   * Hash the block headers.
   * @param {Function} serializedBufferProviderFunc
   * @param {String?} enc - Can be `'hex'` or `null`.
   * @returns {Hash|Buffer} hash
   */

  setHash(serializedBufferProviderFunc, enc) {
    let h = this._hash;

    if (!h) {
      h = hash256.digest(serializedBufferProviderFunc());
      if (!this.mutable)
        this._hash = h;
    }

    if (enc === 'hex') {
      let hex = this._hhash;
      if (!hex) {
        hex = h.toString('hex');
        if (!this.mutable)
          this._hhash = hex;
      }
      h = hex;
    }

    return h;
  }
}

/*
 * Expose
 */

module.exports = HasHashBehavior;
