/*!
 * blockstore/abstract.js - abstract blockstore for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Logger = require('blgr');

/**
 * Abstract Block Store
 *
 * @alias module:blockstore.AbstractBlockStore
 * @abstract
 */

class AbstractBlockStore {
  /**
   * Create an abstract blockstore.
   * @constructor
   */

  constructor(options) {
    this.options = options || {};

    if (this.options.logger != null)
      this.logger = this.options.logger.context('blockstore');
    else
      this.logger = Logger.global.context('blockstore');
  }

  /**
   * This method ensures that resources are available
   * before opening.
   * @returns {Promise}
   */

  async ensure() {
    throw new Error('Abstract method.');
  }

  /**
   * This method opens any necessary resources and
   * initializes the store to be ready to be queried.
   * @returns {Promise}
   */

  async open() {
    throw new Error('Abstract method.');
  }

  /**
   * This method closes resources and prepares
   * the store to be closed.
   * @returns {Promise}
   */

  async close() {
    throw new Error('Abstract method.');
  }

  /**
   * This method stores block undo coin data.
   * @returns {Promise}
   */

  async writeUndo(hash, data) {
    throw new Error('Abstract method.');
  }

  /**
   * This method stores block data.
   * @returns {Promise}
   */

  async write(hash, data) {
    throw new Error('Abstract method.');
  }

  /**
   * This method will retrieve block undo coin data.
   * @returns {Promise}
   */

  async readUndo(hash) {
    throw new Error('Abstract method.');
  }

  /**
   * This method will retrieve block data. Smaller portions of
   * the block can be read by using the offset and size arguments.
   * @returns {Promise}
   */

  async read(hash, offset, size) {
    throw new Error('Abstract method.');
  }

  /**
   * This will free resources for storing the block undo coin data.
   * @returns {Promise}
   */

  async pruneUndo(hash) {
    throw new Error('Abstract method.');
  }

  /**
   * This will free resources for storing the block data.
   * @returns {Promise}
   */

  async prune(hash) {
    throw new Error('Abstract method.');
  }

  /**
   * This will check if a block undo coin data has been stored
   * and is available.
   * @returns {Promise}
   */

  async hasUndo(hash) {
    throw new Error('Abstract method.');
  }

  /**
   * This will check if a block has been stored and is available.
   * @returns {Promise}
   */

  async has(hash) {
    throw new Error('Abstract method.');
  }
}

/*
 * Expose
 */

module.exports = AbstractBlockStore;
