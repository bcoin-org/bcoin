/*!
 * fileloc.js - fileloc object for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');

/**
 * Pointer to a block region
 * @alias module:utils.FileLocation
 * @constructor
 * @param {Number} file
 * @param {Number} offset
 * @param {Number} length
 */

function FileLocation(file, offset, len) {
  if (!(this instanceof FileLocation))
    return new FileLocation(file, offset, len);

  this.file = file;
  this.offset = offset;
  this.len = len;
}

/**
 * Serialize the FileLocation.
 * @returns {Buffer}
 */

FileLocation.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(12);
  bw.writeU32(this.file);
  bw.writeU32(this.offset);
  bw.writeU32(this.len);
  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {FileLocation}
 */

FileLocation.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);
  const file = br.readU32();
  const offset = br.readU32();
  const len = br.readU32();
  const loc = new FileLocation(file, offset, len);
  return loc;
};

/**
 * Instantiate a FileLocation from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {FileLocation}
 */

FileLocation.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new FileLocation().fromRaw(data);
};

module.exports = FileLocation;
