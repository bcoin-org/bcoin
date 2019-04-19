/*!
 * paths.js - paths object for hsd
 * Copyright (c) 2019, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = require('bsert');

/**
 * Paths
 * Represents the HD paths for coins in a single transaction.
 * @alias module:wallet.Paths
 * @property {Map[]} outputs - Paths.
 */

class Paths {
  /**
   * Create paths
   * @constructor
   */

  constructor() {
    this.paths = new Map();
  }

  /**
   * Add a single entry to the collection.
   * @param {Number} index
   * @param {Path} path
   * @returns {Path}
   */

  add(index, path) {
    assert((index >>> 0) === index);
    assert(path);
    this.paths.set(index, path);
    return path;
  }

  /**
   * Test whether the collection has a path.
   * @param {Number} index
   * @returns {Boolean}
   */

  has(index) {
    return this.paths.has(index);
  }

  /**
   * Get a path.
   * @param {Number} index
   * @returns {Path|null}
   */

  get(index) {
    return this.paths.get(index) || null;
  }

  /**
   * Remove a path and return it.
   * @param {Number} index
   * @returns {Path|null}
   */

  remove(index) {
    const path = this.get(index);

    if (!path)
      return null;

    this.paths.delete(index);

    return path;
  }

  /**
   * Test whether there are paths.
   * @returns {Boolean}
   */

  isEmpty() {
    return this.paths.size === 0;
  }
}

/*
 * Expose
 */

module.exports = Paths;
