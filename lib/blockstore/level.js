/*!
 * blockstore/level.js - leveldb blockstore for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');
const fs = require('bfile');
const AbstractBlockStore = require('./abstract');
const layout = require('./layout');
const {types} = require('./common');

/**
 * LevelDB Block Store
 *
 * @alias module:blockstore:LevelBlockStore
 * @abstract
 */

class LevelBlockStore extends AbstractBlockStore {
  /**
   * Create a blockstore that stores blocks in LevelDB.
   * @constructor
   */

  constructor(options) {
    super(options);

    this.location = options.location;

    this.db = bdb.create({
      location: this.location,
      cacheSize: options.cacheSize,
      compression: false,
      memory: options.memory
    });
  }

  /**
   * This method ensures that the storage directory exists
   * before opening.
   * @returns {Promise}
   */

  async ensure() {
    return fs.mkdirp(this.location);
  }

  /**
   * Opens the block storage.
   * @returns {Promise}
   */

  async open() {
    this.logger.info('Opening LevelBlockStore...');

    await this.db.open();
    await this.db.verify(layout.V.encode(), 'levelblockstore', 0);
  }

  /**
   * Closes the block storage.
   */

  async close() {
    this.logger.info('Closing LevelBlockStore...');

    await this.db.close();
  }

  /**
   * This method stores merkle block data in LevelDB.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async writeMerkle(hash, data) {
    return this.db.put(layout.b.encode(types.MERKLE, hash), data);
  }

  /**
   * This method stores block undo coin data in LevelDB.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async writeUndo(hash, data) {
    return this.db.put(layout.b.encode(types.UNDO, hash), data);
  }

  /**
   * This method stores block data in LevelDB.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async write(hash, data) {
    return this.db.put(layout.b.encode(types.BLOCK, hash), data);
  }

  /**
   * This method stores serialized block filter data in LevelDB.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The serialized block filter data.
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async writeFilter(hash, data, filterType) {
    return this.db.put(layout.b.encode(filterType, hash), data);
  }

  /**
   * This method will retrieve merkle block data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async readMerkle(hash) {
    return this.db.get(layout.b.encode(types.MERKLE, hash));
  }

  /**
   * This method will retrieve block undo coin data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async readUndo(hash) {
    return this.db.get(layout.b.encode(types.UNDO, hash));
  }

  /**
   * This method will retrieve serialized block filter data.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async readFilter(hash, filterType) {
    return this.db.get(layout.b.encode(filterType, hash));
  }

  /**
   * This method will retrieve block filter header only.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType- The filter type
   * @returns {Promise}
   */

  async readFilterHeader(hash, filterType) {
    const data = await this.db.get(layout.b.encode(filterType, hash));

    if (!data)
      return null;

    return data.slice(0, 32);
  }

  /**
   * This method will retrieve block data. Smaller portions of the
   * block (e.g. transactions) can be returned using the offset and
   * length arguments. However, the entire block will be read as the
   * data is stored in a key/value database.
   * @param {Buffer} hash - The block hash
   * @param {Number} offset - The offset within the block
   * @param {Number} length - The number of bytes of the data
   * @returns {Promise}
   */

  async read(hash, offset, length) {
    let raw = await this.db.get(layout.b.encode(types.BLOCK, hash));

    if (offset) {
      if (offset + length > raw.length)
        throw new Error('Out-of-bounds read.');

      raw = raw.slice(offset, offset + length);
    }

    return raw;
  }

  /**
   * This will free resources for storing merkle block data.
   * The block data may not be immediately removed from disk, and will
   * be reclaimed during LevelDB compaction.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async pruneMerkle(hash) {
    if (!await this.hasMerkle(hash))
      return false;

    await this.db.del(layout.b.encode(types.MERKLE, hash));

    return true;
  }

  /**
   * This will free resources for storing the block undo coin data.
   * The block data may not be immediately removed from disk, and will
   * be reclaimed during LevelDB compaction.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async pruneUndo(hash) {
    if (!await this.hasUndo(hash))
      return false;

    await this.db.del(layout.b.encode(types.UNDO, hash));

    return true;
  }

  /**
   * This will free resources for storing the serialized block filter data.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async pruneFilter(hash, filterType) {
    if (!await this.hasFilter(hash, filterType))
      return false;

    await this.db.del(layout.b.encode(filterType, hash));

    return true;
  }

  /**
   * This will free resources for storing the block data. The block
   * data may not be immediately removed from disk, and will be reclaimed
   * during LevelDB compaction.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async prune(hash) {
    if (!await this.has(hash))
      return false;

    await this.db.del(layout.b.encode(types.BLOCK, hash));

    return true;
  }

  /**
   * This will check if a merkle block data has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async hasMerkle(hash) {
    return this.db.has(layout.b.encode(types.MERKLE, hash));
  }

  /**
   * This will check if a block undo coin data has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async hasUndo(hash) {
    return this.db.has(layout.b.encode(types.UNDO, hash));
  }

  /**
   * This will check if a block filter has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async hasFilter(hash, filterType) {
    return this.db.has(layout.b.encode(filterType, hash));
  }

  /**
   * This will check if a block has been stored and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async has(hash) {
    return this.db.has(layout.b.encode(types.BLOCK, hash));
  }
}

/*
 * Expose
 */

module.exports = LevelBlockStore;
