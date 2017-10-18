'use strict';

const stream = require('stream');
const util = require('../utils/util');
const Network = require('../protocol/network');

function BlockStream(options) {
  stream.Transform.call(this);

  this.network = Network.primary;
  if (options.network != null)
    this.network = Network.get(options.network);

  const magic = util.revHex(util.hex32(this.network.magic));
  this.delimiter = Buffer.from(magic, 'hex');
  this._stub = Buffer.from('');
};

Object.setPrototypeOf(BlockStream.prototype, stream.Transform.prototype);

BlockStream.prototype._transform = function _transform(chunk, encoding, done) {
  this._stub = Buffer.concat([this._stub, chunk]);

  for (;;) {
    let start = this._stub.indexOf(this.delimiter);

    if (start === -1 || this._stub.length < start+8)
      break;

    const len = this._stub.readUInt32LE(start+4, start+8);

    if (this._stub.length < start+8+len)
      break;

    this.push(this._stub.slice(start+8, start+8+len));
    this._stub = this._stub.slice(start+len+4);
    start = start + len + 12;
  }
  done();
};

BlockStream.prototype._flush = function _flush(done) {
  this.push(this._stub.slice(8, -4));
  done();
};

BlockStream.createBlockStream = function createBlockStream(options) {
  return new BlockStream(options);
};

module.exports = BlockStream;
