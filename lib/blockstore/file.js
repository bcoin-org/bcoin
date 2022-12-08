/*!
 * blockstore/file.js - file blockstore for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {isAbsolute, resolve, join} = require('path');
const bdb = require('bdb');
const assert = require('bsert');
const fs = require('bfile');
const bio = require('bufio');
const hash256 = require('bcrypto/lib/hash256');
const Network = require('../protocol/network');
const AbstractBlockStore = require('./abstract');
const {BlockRecord, FileRecord} = require('./records');
const layout = require('./layout');
const {types, prefixes, filters} = require('./common');

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
    super(options);

    assert(isAbsolute(options.location), 'Location not absolute.');

    this.location = options.location;
    this.indexLocation = resolve(this.location, './index');

    this.db = bdb.create({
      location: this.indexLocation,
      cacheSize: options.cacheSize,
      compression: false
    });

    this.maxFileLength = options.maxFileLength || 128 * 1024 * 1024;

    assert(Number.isSafeInteger(this.maxFileLength),
      'Invalid max file length.');

    this.network = Network.primary;

    if (options.network != null)
      this.network = Network.get(options.network);

    this.writing = Object.create(null);
  }

  /**
   * Compares the number of files in the directory
   * with the recorded number of files.
   * @param {Number} type - The type of block data
   * @private
   * @returns {Promise}
   */

  async check(type) {
    const prefix = prefixes[type];
    const regexp = new RegExp(`^${prefix}(\\d{5})\\.dat$`);
    const all = await fs.readdir(this.location);
    const dats = all.filter(f => regexp.test(f));
    const filenos = dats.map(f => parseInt(f.match(regexp)[1]));

    let missing = false;

    for (const fileno of filenos) {
      const rec = await this.db.get(layout.f.encode(type, fileno));
      if (!rec) {
        missing = true;
        break;
      }
    }

    return {missing, filenos};
  }

  /**
   * Creates indexes from files for a block type. Reads the hash of
   * the block data from the magic prefix, except for a block which
   * the hash is read from the block header.
   * @private
   * @param {Number} type - The type of block data
   * @returns {Promise}
   */

  async _index(type) {
    const {missing, filenos} = await this.check(type);

    if (!missing)
      return;

    this.logger.info('Indexing block type %d...', type);

    for (const fileno of filenos) {
      const b = this.db.batch();
      const filepath = this.filepath(type, fileno);
      const data = await fs.readFile(filepath);
      const reader = bio.read(data);
      let magic = null;
      let blocks = 0;

      while (reader.left() >= 4) {
        magic = reader.readU32();

        // Move forward a byte from the last read
        // if the magic doesn't match.
        if (magic !== this.network.magic) {
          reader.seek(-3);
          continue;
        }

        let hash = null;
        let position = 0;
        let length = 0;

        try {
          length = reader.readU32();

          if (type === types.BLOCK || type === types.MERKLE) {
            position = reader.offset;
            hash = hash256.digest(reader.readBytes(80, true));
            reader.seek(length - 80);
          } else {
            hash = reader.readHash();
            position = reader.offset;
            reader.seek(length);
          }
        } catch (err) {
          this.logger.warning(
            'Unknown block in file: %s, reason: %s',
            filepath, err.message);
          continue;
        }

        const blockrecord = new BlockRecord({
          file: fileno,
          position: position,
          length: length
        });

        blocks += 1;
        b.put(layout.b.encode(type, hash), blockrecord.toRaw());
      }

      const filerecord = new FileRecord({
        blocks: blocks,
        used: reader.offset,
        length: this.maxFileLength
      });

      b.put(layout.f.encode(type, fileno), filerecord.toRaw());

      await b.write();

      this.logger.info('Indexed %d blocks (file=%s).', blocks, filepath);
    }
  }

  /**
   * Compares the number of files in the directory
   * with the recorded number of files. If there are any
   * inconsistencies it will reindex all blocks.
   * @private
   * @returns {Promise}
   */

  async index() {
    await this._index(types.BLOCK);
    await this._index(types.MERKLE);
    await this._index(types.UNDO);
    for (const filter in filters) {
      await this._index(filters[filter]);
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
   * indexing databases.
   */

  async close() {
    this.logger.info('Closing FileBlockStore...');

    await this.db.close();
  }

  /**
   * This method will determine the file path based on the file number
   * and the current block data location.
   * @private
   * @param {Number} type - The type of block data
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
   * write a block based on the size and type.
   * @private
   * @param {Number} type - The type of block data
   * @param {Number} length - The number of bytes
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
      fileno = bio.readU32(last, 0);

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
   * This method stores merkle block data in files.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async writeMerkle(hash, data) {
    return this._write(types.MERKLE, hash, data);
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
   * This method stores serialized block filter data in files.
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The serialized block filter data.
   * @param {Number} filterType - The filter type.
   * @returns {Promise}
   */

  async writeFilter(hash, data, filterType) {
    return this._write(filterType, hash, data);
  }

  /**
   * This method stores block data in files with by appending
   * data to the last written file and updating indexes to point
   * to the file and position.
   * @private
   * @param {Number} type - The type of block data
   * @param {Buffer} hash - The block hash
   * @param {Buffer} data - The block data
   * @returns {Promise}
   */

  async _write(type, hash, data) {
    if (this.writing[type])
      throw new Error('Already writing.');

    this.writing[type] = true;

    if (await this.db.has(layout.b.encode(type, hash))) {
      this.writing[type] = false;
      return false;
    }

    let mlength = 8;

    // Hash for a block is not stored with
    // the magic prefix as it's read from the header
    // of the block data.
    if (type !== types.BLOCK && type !== types.MERKLE)
      mlength += 32;

    const blength = data.length;
    const length = data.length + mlength;

    const bwm = bio.write(mlength);

    bwm.writeU32(this.network.magic);
    bwm.writeU32(blength);

    if (type !== types.BLOCK && type !== types.MERKLE)
      bwm.writeHash(hash);

    const magic = bwm.render();

    const {
      fileno,
      filerecord,
      filepath
    } = await this.allocate(type, length);

    const mposition = filerecord.used;
    const bposition = filerecord.used + mlength;

    const fd = await fs.open(filepath, 'r+');

    let mwritten = 0;
    let bwritten = 0;

    try {
      mwritten = await fs.write(fd, magic, 0, mlength, mposition);
      bwritten = await fs.write(fd, data, 0, blength, bposition);
    } finally {
      await fs.close(fd);
    }

    if (mwritten !== mlength) {
      this.writing[type] = false;
      throw new Error('Could not write block magic.');
    }

    if (bwritten !== blength) {
      this.writing[type] = false;
      throw new Error('Could not write block.');
    }

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

    this.writing[type] = false;

    return true;
  }

  /**
   * This method will retrieve merkle block data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async readMerkle(hash) {
    return this._read(types.MERKLE, hash);
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
   * This method will retrieve serialized block filter data.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async readFilter(hash, filterType) {
    return this._read(filterType, hash);
  }

  /**
   * This method will retrieve block filter header only.
   * @param {Buffer} hash - The block hash
   * @param {String} filterType - The filter name
   * @returns {Promise}
   */

  async readFilterHeader(hash, filterType) {
    return this._read(filterType, hash, 0, 32);
  }

  /**
   * This methods reads data from disk by retrieving the index of
   * the data and reading from the corresponding file and location.
   * @private
   * @param {Number} type - The type of block data
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

    if (!length && offset > 0)
      length = blockrecord.length - offset;

    if (!length)
      length = blockrecord.length;

    if (offset + length > blockrecord.length)
      throw new Error('Out-of-bounds read.');

    const data = Buffer.alloc(length);

    const fd = await fs.open(filepath, 'r');
    let bytes = 0;

    try {
      bytes = await fs.read(fd, data, 0, length, position);
    } finally {
      await fs.close(fd);
    }

    if (bytes !== length)
      throw new Error('Wrong number of bytes read.');

    return data;
  }

  /**
   * This will free resources for storing merkle block data.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async pruneMerkle(hash) {
    return this._prune(types.MERKLE, hash);
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
   * This will free resources for storing the serialized block filter data.
   * @param {Buffer} hash - The block hash
   * @param {String} filterType - The filter type
   * @returns {Promise}
   */

  async pruneFilter(hash, filterType) {
    return this._prune(filterType, hash);
  }

  /**
   * This will free resources for storing the block data. The block
   * data may not be deleted from disk immediately, the index for the
   * block is removed and will not be able to be read. The underlying
   * file is unlinked when all blocks in a file have been pruned.
   * @private
   * @param {Number} type
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
   * This will check if merkle block data has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @returns {Promise}
   */

  async hasMerkle(hash) {
    return await this.db.has(layout.b.encode(types.MERKLE, hash));
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
   * This will check if a block filter has been stored
   * and is available.
   * @param {Buffer} hash - The block hash
   * @param {Number} filterType - The filter type
   * @returns {Promise}
   */

  async hasFilter(hash, filterType) {
    return await this.db.has(layout.b.encode(filterType, hash));
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
