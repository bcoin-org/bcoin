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
    this.db = bdb.create({
      location: resolve(this.location, './index')
    });
    this.maxFileLength = options.maxFileLength || 128 * 1024 * 1024;

    this.network = Network.primary;

    if (options.network != null)
      this.network = Network.get(options.network);
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
      const rec = await this.db.get(layout.f.encode(fileno));
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
      const filepath = this.filepath(fileno);
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
        b.put(layout.b.encode(hash), blockrecord.toRaw());
      }

      const filerecord = new FileRecord({
        blocks: blocks,
        used: reader.offset,
        length: this.maxFileLength
      });

      b.put(layout.f.encode(fileno), filerecord.toRaw());

      await b.write();

      this.logger.info(`Indexed ${blocks} blocks from ${filepath}...`);
    }
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
   * @param {Number} fileno - The number of the file.
   * @returns {Promise}
   */

  filepath(fileno) {
    const pad = 5;

    let num = fileno.toString(10);

    if (num.length > pad)
      throw new Error('File number too large.');

    while (num.length < pad)
      num = `0${num}`;

    return join(this.location, `blk${num}.dat`);
  }

  /**
   * This method will select and potentially allocate a file to
   * write a block based on the size.
   * @param {Number} length - The number of bytes of the data to be written.
   * @returns {Promise}
   */

  async allocate(length) {
    if (length > this.maxFileLength)
      throw new Error('Block length above max file length.');

    let fileno = 0;
    let filerecord = null;
    let filepath = null;

    const last = await this.db.get(layout.R.encode());
    if (last)
      fileno = bio.read(last).readU32();

    filepath = this.filepath(fileno);

    const rec = await this.db.get(layout.f.encode(fileno));

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
      filepath = this.filepath(fileno);
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
   * This method stores block data in files.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async write(hash, data) {
    const mlength = 8;
    const blength = data.length;
    const length = data.length + mlength;

    const {
      fileno,
      filerecord,
      filepath
    } = await this.allocate(length);

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

    b.put(layout.b.encode(hash), blockrecord.toRaw());
    b.put(layout.f.encode(fileno), filerecord.toRaw());

    const bw = bio.write(4);
    b.put(layout.R.encode(), bw.writeU32(fileno).render());

    await b.write();
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
    const raw = await this.db.get(layout.b.encode(hash));
    if (!raw)
      return null;

    const blockrecord = BlockRecord.fromRaw(raw);

    const filepath = this.filepath(blockrecord.file);

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
   * This will free resources for storing the block data. The block
   * data may not be deleted from disk immediately, the index for
   * the block is removed and will not be able to be read. The underlying
   * file is unlinked when all blocks in a file have been pruned.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async prune(hash) {
    const braw = await this.db.get(layout.b.encode(hash));
    if (!braw)
      return false;

    const blockrecord = BlockRecord.fromRaw(braw);

    const fraw = await this.db.get(layout.f.encode(blockrecord.file));
    if (!fraw)
      return false;

    const filerecord = FileRecord.fromRaw(fraw);

    filerecord.blocks -= 1;

    const b = this.db.batch();

    if (filerecord.blocks === 0)
      b.del(layout.f.encode(blockrecord.file));
    else
      b.put(layout.f.encode(blockrecord.file), filerecord.toRaw());

    b.del(layout.b.encode(hash));

    await b.write();

    if (filerecord.blocks === 0)
      await fs.unlink(this.filepath(blockrecord.file));

    return true;
  }

  /**
   * This will check if a block has been stored and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async has(hash) {
    return await this.db.has(layout.b.encode(hash));
  }
}

/*
 * Expose
 */

module.exports = FileBlockStore;
