/*!
 * blockstore/abstract.js - abstract block store for bcoin
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
   * This method opens any necessary resources and
   * initializes the store to be ready to be queried.
   * @returns {Promise}
   */

  async open() {
    throw new Error('Abstract method.');
  }

  /**
   * This method closes resources and prepares
   * store to be closed.
   * @returns {Promise}
   */

  async close() {
    throw new Error('Abstract method.');
  }

  /**
   * This method stores block data. The action should be idempotent.
   * If the data is already stored, the behavior will be the same. Any
   * concurrent requests to store the same data will produce the same
   * result, and will not conflict with each other.
   * @returns {Promise}
   */

  async write(hash, data) {
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
   * This will free resources for storing the block data. This
   * may not mean that the block is deleted, but that it should
   * no longer consume any local storage resources.
   * @returns {Promise}
   */

  async prune(hash) {
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
