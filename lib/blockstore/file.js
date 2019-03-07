/*!
 * blockstore/file.js - file block store for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {isAbsolute, resolve, join} = require('path');
const bdb = require('bdb');
const assert = require('bsert');
const fs = require('bfile');
const bio = require('bufio');
const Network = require('../protocol/network');
const Block = require('../primitives/block');
const AbstractBlockStore = require('./abstract');
const {BlockRecord, FileRecord} = require('./records');
const layout = require('./layout');
const {types, prefixes} = require('./common');

/**
 * File Block Store
 *
 * @alias module:blockstore:FileBlockStore
 * @abstract
 */

class FileBlockStore extends AbstractBlockStore {
  /**
   * Create a blockstore that stores blocks in files.
   * @constructor
   */

  constructor(options) {
    super();

    assert(isAbsolute(options.location), 'Location not absolute.');

    this.location = options.location;
    this.indexLocation = resolve(this.location, './index');

    this.db = bdb.create({
      location: this.indexLocation,
      cacheSize: options.cacheSize,
      compression: false
    });

    this.maxFileLength = options.maxFileLength || 128 * 1024 * 1024;

    this.network = Network.primary;

    if (options.network != null)
      this.network = Network.get(options.network);

    this.writing = false;
  }

  /**
   * Compares the number of files in the directory
   * with the recorded number of files. If there are any
   * inconsistencies it will reindex all blocks.
   * @private
   * @returns {Promise}
   */

  async index() {
    const regexp = /^blk(\d{5})\.dat$/;
    const all = await fs.readdir(this.location);
    const dats = all.filter(f => regexp.test(f));
    const filenos = dats.map(f => parseInt(f.match(regexp)[1]));

    let missing = false;

    for (const fileno of filenos) {
      const rec = await this.db.get(layout.f.encode(types.BLOCK, fileno));
      if (!rec) {
        missing = true;
        break;
      }
    }

    if (!missing)
      return;

    this.logger.info('Indexing FileBlockStore...');

    for (const fileno of filenos) {
      const b = this.db.batch();
      const filepath = this.filepath(types.BLOCK, fileno);
      const data = await fs.readFile(filepath);
      const reader = bio.read(data);
      let magic = null;
      let blocks = 0;

      while (reader.left() >= 4) {
        magic = reader.readU32();
        if (magic !== this.network.magic) {
          reader.seek(4);
          continue;
        }

        const length = reader.readU32();
        const position = reader.offset;

        const block = Block.fromReader(reader);
        const hash = block.hash();

        const blockrecord = new BlockRecord({
          file: fileno,
          position: position,
          length: length
        });

        blocks += 1;
        b.put(layout.b.encode(types.BLOCK, hash), blockrecord.toRaw());
      }

      const filerecord = new FileRecord({
        blocks: blocks,
        used: reader.offset,
        length: this.maxFileLength
      });

      b.put(layout.f.encode(types.BLOCK, fileno), filerecord.toRaw());

      await b.write();

      this.logger.info(`Indexed ${blocks} blocks from ${filepath}...`);
    }
  }

  /**
   * This method ensures that both the block storage directory
   * and index directory exist.
   * before opening.
   * @returns {Promise}
   */

  async ensure() {
    return fs.mkdirp(this.indexLocation);
  }

  /**
   * Opens the file block store. It will regenerate necessary block
   * indexing if the index is missing or inconsistent.
   * @returns {Promise}
   */

  async open() {
    this.logger.info('Opening FileBlockStore...');

    await this.db.open();
    await this.db.verify(layout.V.encode(), 'fileblockstore', 0);

    await this.index();
  }

  /**
   * This closes the file block store and underlying
   * databases for indexing.
   */

  async close() {
    this.logger.info('Closing FileBlockStore...');

    await this.db.close();
  }

  /**
   * This method will determine the file path based on the file number
   * and the current block data location.
   * @private
   * @param {Number} fileno - The number of the file.
   * @returns {Promise}
   */

  filepath(type, fileno) {
    const pad = 5;

    let num = fileno.toString(10);

    if (num.length > pad)
      throw new Error('File number too large.');

    while (num.length < pad)
      num = `0${num}`;

    let filepath = null;

    const prefix = prefixes[type];

    if (!prefix)
      throw new Error('Unknown file prefix.');

    filepath = join(this.location, `${prefix}${num}.dat`);

    return filepath;
  }

  /**
   * This method will select and potentially allocate a file to
   * write a block based on the size.
   * @private
   * @param {Number} length - The number of bytes of the data to be written.
   * @returns {Promise}
   */

  async allocate(type, length) {
    if (length > this.maxFileLength)
      throw new Error('Block length above max file length.');

    let fileno = 0;
    let filerecord = null;
    let filepath = null;

    const last = await this.db.get(layout.F.encode(type));
    if (last)
      fileno = bio.read(last).readU32();

    filepath = this.filepath(type, fileno);

    const rec = await this.db.get(layout.f.encode(type, fileno));

    let touch = false;

    if (rec) {
      filerecord = FileRecord.fromRaw(rec);
    } else {
      touch = true;
      filerecord = new FileRecord({
        blocks: 0,
        used: 0,
        length: this.maxFileLength
      });
    }

    if (filerecord.used + length > filerecord.length) {
      fileno += 1;
      filepath = this.filepath(type, fileno);
      touch = true;
      filerecord = new FileRecord({
        blocks: 0,
        used: 0,
        length: this.maxFileLength
      });
    }

    if (touch) {
      const fd = await fs.open(filepath, 'w');
      await fs.close(fd);
    }

    return {fileno, filerecord, filepath};
  }

  /**
   * This method stores block undo coin data in files.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async writeUndo(hash, data) {
    return this._write(types.UNDO, hash, data);
  }

  /**
   * This method stores block data in files.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async write(hash, data) {
    return this._write(types.BLOCK, hash, data);
  }

  /**
   * This method stores block data in files with by appending
   * data to the last written file and updating indexes to point
   * to the file and position.
   * @private
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async _write(type, hash, data) {
    if (this.writing)
      throw new Error('Already writing.');

    this.writing = true;

    const mlength = 8;
    const blength = data.length;
    const length = data.length + mlength;

    const {
      fileno,
      filerecord,
      filepath
    } = await this.allocate(type, length);

    const mposition = filerecord.used;
    const bposition = filerecord.used + mlength;

    const bwm = bio.write(mlength);
    bwm.writeU32(this.network.magic);
    bwm.writeU32(blength);
    const magic = bwm.render();

    const fd = await fs.open(filepath, 'r+');

    const mwritten = await fs.write(fd, magic, 0, mlength, mposition);
    const bwritten = await fs.write(fd, data, 0, blength, bposition);

    await fs.close(fd);

    if (mwritten !== mlength)
      throw new Error('Could not write block magic.');

    if (bwritten !== blength)
      throw new Error('Could not write block.');

    filerecord.blocks += 1;
    filerecord.used += length;

    const b = this.db.batch();

    const blockrecord = new BlockRecord({
      file: fileno,
      position: bposition,
      length: blength
    });

    b.put(layout.b.encode(type, hash), blockrecord.toRaw());
    b.put(layout.f.encode(type, fileno), filerecord.toRaw());

    const last = bio.write(4).writeU32(fileno).render();
    b.put(layout.F.encode(type), last);

    await b.write();

    this.writing = false;
  }

  /**
   * This method will retrieve block undo coin data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async readUndo(hash) {
    return this._read(types.UNDO, hash);
  }

  /**
   * This method will retrieve block data. Smaller portions of the
   * block (e.g. transactions) can be read by using the offset and
   * length arguments.
   * @param {Buffer} hash - The block hash
   * @param {Number} offset - The offset within the block
   * @param {Number} length - The number of bytes of the data
   * @returns {Promise}
   */

  async read(hash, offset, length) {
    return this._read(types.BLOCK, hash, offset, length);
  }

  /**
   * This methods reads data from disk by retrieving the index of
   * the data and reading from the correponding file and location.
   * @private
   * @param {Buffer} type - The data type
   * @param {Buffer} hash - The block hash
   * @param {Number} offset - The offset within the block
   * @param {Number} length - The number of bytes of the data
   * @returns {Promise}
   */

  async _read(type, hash, offset, length) {
    const raw = await this.db.get(layout.b.encode(type, hash));
    if (!raw)
      return null;

    const blockrecord = BlockRecord.fromRaw(raw);

    const filepath = this.filepath(type, blockrecord.file);

    let position = blockrecord.position;

    if (offset)
      position += offset;

    if (!length)
      length = blockrecord.length;

    if (offset + length > blockrecord.length)
      throw new Error('Out-of-bounds read.');

    const data = Buffer.alloc(length);

    const fd = await fs.open(filepath, 'r');
    await fs.read(fd, data, 0, length, position);
    await fs.close(fd);

    return data;
  }

  /**
   * This will free resources for storing the block undo coin data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async pruneUndo(hash) {
    return this._prune(types.UNDO, hash);
  }

  /**
   * This will free resources for storing the block data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async prune(hash) {
    return this._prune(types.BLOCK, hash);
  }

  /**
   * This will free resources for storing the block data. The block
   * data may not be deleted from disk immediately, the index for the
   * block is removed and will not be able to be read. The underlying
   * file is unlinked when all blocks in a file have been pruned.
   * @private
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async _prune(type, hash) {
    const braw = await this.db.get(layout.b.encode(type, hash));
    if (!braw)
      return false;

    const blockrecord = BlockRecord.fromRaw(braw);

    const fraw = await this.db.get(layout.f.encode(type, blockrecord.file));
    if (!fraw)
      return false;

    const filerecord = FileRecord.fromRaw(fraw);

    filerecord.blocks -= 1;

    const b = this.db.batch();

    if (filerecord.blocks === 0)
      b.del(layout.f.encode(type, blockrecord.file));
    else
      b.put(layout.f.encode(type, blockrecord.file), filerecord.toRaw());

    b.del(layout.b.encode(type, hash));

    await b.write();

    if (filerecord.blocks === 0)
      await fs.unlink(this.filepath(type, blockrecord.file));

    return true;
  }

  /**
   * This will check if a block undo coin has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async hasUndo(hash) {
    return await this.db.has(layout.b.encode(types.UNDO, hash));
  }

  /**
   * This will check if a block has been stored and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async has(hash) {
    return await this.db.has(layout.b.encode(types.BLOCK, hash));
  }
}

/*
 * Expose
 */

module.exports = FileBlockStore;