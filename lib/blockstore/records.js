/*!
 * blockstore/records.js - blockstore records
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');

/**
 * @module blockstore/records
 */

/**
 * Block Record
 */

class BlockRecord extends bio.Struct {
  /**
   * Create a block record.
   * @constructor
   */

  constructor(options = {}) {
    super();

    this.file = options.file || 0;
    this.position = options.position || 0;
    this.length = options.length || 0;

    assert((this.file >>> 0) === this.file);
    assert((this.position >>> 0) === this.position);
    assert((this.length >>> 0) === this.length);
  }

  /**
   * Get serialization size.
   * @return {Number}
   */

  getSize() {
    return 12;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.file = br.readU32();
    this.position = br.readU32();
    this.length = br.readU32();

    return this;
  }

  /**
   * Serialize the block record.
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU32(this.file);
    bw.writeU32(this.position);
    bw.writeU32(this.length);

    return bw;
  }
}

/**
 * File Record
 */

class FileRecord extends bio.Struct {
  /**
   * Create a file record.
   * @constructor
   */

  constructor(options = {}) {
    super();

    this.blocks = options.blocks || 0;
    this.used = options.used || 0;
    this.length = options.length || 0;

    assert((this.blocks >>> 0) === this.blocks);
    assert((this.used >>> 0) === this.used);
    assert((this.length >>> 0) === this.length);
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 12;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.blocks = br.readU32();
    this.used = br.readU32();
    this.length = br.readU32();

    return this;
  }

  /**
   * Serialize the file record.
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU32(this.blocks);
    bw.writeU32(this.used);
    bw.writeU32(this.length);

    return bw;
  }
}

/*
 * Expose
 */

exports.BlockRecord = BlockRecord;
exports.FileRecord = FileRecord;

module.exports = exports;
