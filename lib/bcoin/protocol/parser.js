var assert = require('assert');
var util = require('util');
var Transform = require('stream').Transform;

var bspv = require('../../bspv');
var utils = bspv.utils;
var constants = require('./constants');

function Parser(peer) {
  if (!(this instanceof Parser))
    return new Parser(peer);

  Transform.call(this);
  this._readableState.objectMode = true;

  this.peer = peer;

  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 24;
  this.packet = null;
}
util.inherits(Parser, Transform);
module.exports = Parser;

Parser.prototype._transform = function(data, enc, cb) {
  if (data) {
    this.pendingTotal += data.length;
    this.pending.push(data);
  }
  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    var chunk = new Buffer(this.waiting);
    console.log(this.pending);
    for (var i = 0, off = 0, len = 0; off < chunk.length; i++) {
      len = this.pending[i].copy(chunk, off);
      off += len;
    }
    assert.equal(off, chunk.length);

    // Slice buffers
    this.pending = this.pending.slice();
    this.pendingTotal -= chunk.length;
    if (this.pending.length && len !== this.pending[0].length)
      this.pending[0] = this.pending[0].slice(len);

    this.parse(chunk);
  }
  cb();
};

Parser.prototype.parse = function parse(chunk) {
  if (this.packet === null) {
    this.packet = this.parseHeader(chunk);
  } else {
    this.packet.payload = chunk;
    if (utils.checksum(this.packet.payload) !== this.packet.checksum)
      return this.emit('error', new Error('Invalid checksum'));
    this.push(this.packet);

    this.waiting = 24;
    this.packet = null;
  }
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var magic = h.readUInt32LE(0);
  if (magic !== constants.magic) {
    return this.emit('error',
                     new Error('Invalid magic value: ' + magic.toString(16)));
  }

  // Count length of the cmd
  for (var i = 0; h[i + 4] !== 0 && i < 12; i++);
  if (i === 12)
    return this.emit('error', new Error('Not NULL-terminated cmd'));

  var cmd = h.slice(4, 4 + i).toString();
  this.waiting = h.readUInt32LE(16);

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: h.readUInt32LE(20)
  };
};
