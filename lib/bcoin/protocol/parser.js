var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../../bcoin');
var utils = bcoin.utils;
var constants = require('./constants');

var readU32 = utils.readU32;
var readU64 = utils.readU64;

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 24;
  this.packet = null;
}
util.inherits(Parser, EventEmitter);
module.exports = Parser;

Parser.prototype.execute = function(data) {
  if (data) {
    this.pendingTotal += data.length;
    this.pending.push(data);
  }
  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    var chunk = new Array(this.waiting);
    for (var i = 0, off = 0, len = 0; off < chunk.length; i++) {
      len = utils.copy(this.pending[i], chunk, off);
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
};

Parser.prototype.parse = function parse(chunk) {
  if (this.packet === null) {
    this.packet = this.parseHeader(chunk);
  } else {
    this.packet.payload = chunk;
    if (readU32(utils.checksum(this.packet.payload)) !== this.packet.checksum)
      return this.emit('error', new Error('Invalid checksum'));
    this.packet.payload = this.parsePayload(this.packet.cmd,
                                            this.packet.payload);
    this.emit('packet', this.packet);

    this.waiting = 24;
    this.packet = null;
  }
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var magic = readU32(h, 0);
  if (magic !== constants.magic) {
    return this.emit('error',
                     new Error('Invalid magic value: ' + magic.toString(16)));
  }

  // Count length of the cmd
  for (var i = 0; h[i + 4] !== 0 && i < 12; i++);
  if (i === 12)
    return this.emit('error', new Error('Not NULL-terminated cmd'));

  var cmd = utils.stringify(h.slice(4, 4 + i));
  this.waiting = readU32(h, 16);

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: readU32(h, 20)
  };
};

Parser.prototype.parsePayload = function parsePayload(cmd, p) {
  if (cmd === 'version')
    return this.parseVersion(p);
  else
    return this.emit('error', new Error('Unknown packet: ' + cmd));
};

Parser.prototype.parseVersion = function parseVersion(p) {
  if (p.length < 85)
    return this.emit('error', new Error('version packet is too small'));

  var v = readU32(p, 0);
  if (v < constants.minVersion)
    return this.emit('error', new Error('version number is too small'));

  var services = readU64(p, 4);

  // Timestamp
  var ts = readU64(p, 12);

  // Nonce, very dramatic
  var nonce = { lo: readU32(p, 72), hi: readU32(p, 76) };

  // Start height
  var weight = readU32(p, 81);

  // Relay
  var relay = p.length >= 86 ? p[85] === 1 : true;

  return {
    v: v,
    services: services,
    ts: ts,
    nonce: nonce,
    weight: weight,
    relay: relay
  };
};
