var assert = require('assert');

var bcoin = require('../../bcoin');
var constants = require('./constants');
var utils = bcoin.utils;

var writeU32 = utils.writeU32;
var writeAscii = utils.writeAscii;

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();
}
module.exports = Framer;

Framer.prototype.header = function header(cmd, payload) {
  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  var h = new Array(24);

  // Magic value
  writeU32(h, constants.magic, 0);

  // Command
  var len = writeAscii(h, cmd, 4);
  for (var i = 4 + len; i < 4 + 12; i++)
    h[i] = 0;

  // Payload length
  writeU32(h, payload.length, 16);

  // Checksum
  utils.copy(utils.checksum(payload), h, 20);

  return h;
};

Framer.prototype.packet = function packet(cmd, payload) {
  var h = this.header(cmd, payload);
  return h.concat(payload);
};

Framer.prototype._addr = function addr(buf, off) {
  writeU32(buf, 1, off);
  writeU32(buf, 0, off + 4);
  writeU32(buf, 0, off + 8);
  writeU32(buf, 0, off + 12);
  writeU32(buf, 0xffff0000, off + 16);
  writeU32(buf, 0, off + 20);
  buf[off + 24] = 0;
  buf[off + 25] = 0;
};

Framer.prototype.version = function version(packet) {
  var p = new Array(86);

  if (!packet)
    packet = {};

  // Version
  writeU32(p, constants.version, 0);

  // Services
  writeU32(p, constants.services.network, 4);
  writeU32(p, 0, 8);

  // Timestamp
  var ts = ((+new Date) / 1000) | 0;
  writeU32(p, ts, 12);
  writeU32(p, 0, 16);

  // Remote and local addresses
  this._addr(p, 20);
  this._addr(p, 46);

  // Nonce, very dramatic
  writeU32(p, (Math.random() * 0xffffffff) | 0, 72);
  writeU32(p, (Math.random() * 0xffffffff) | 0, 76);

  // No user-agent
  p[80] = 0;

  // Start height
  writeU32(p, packet.height, 81);

  // Relay
  p[85] = packet.relay ? 1 : 0;

  return this.packet('version', p);
};

Framer.prototype.verack = function verack() {
  return this.packet('verack', []);
};

function varint(arr, value, off) {
  if (!off)
    off = 0;
  if (value < 0xfd) {
    arr[off] = value;
    return 1;
  } else if (value <= 0xffff) {
    arr[off] = 0xfd;
    arr[off + 1] = value & 0xff;
    arr[off + 2] = value >>> 8;
    return 3;
  } else if (value <= 0xffffffff) {
    arr[off] = 0xfd;
    arr[off + 3] = value & 0xff;
    arr[off + 4] = (value >>> 8) & 0xff;
    arr[off + 5] = (value >>> 16) & 0xff;
    arr[off + 6] = value >>> 24;
    return 5;
  } else {
    throw new Error('64bit varint not supported yet');
  }
}

Framer.prototype._inv = function _inv(command, items) {
  var res = [];
  var off = varint(res, items.length, 0);
  assert(items.length <= 50000);

  for (var i = 0; i < items.length; i++) {
    // Type
    off += writeU32(res, constants.inv[items[i].type], off);

    // Hash
    var hash = items[i].hash;
    if (typeof hash === 'string')
      hash = utils.toArray(hash, 'hex');
    assert.equal(hash.length, 32);
    res = res.concat(hash);

    off += hash.length;
  }

  return this.packet(command, res);
};

Framer.prototype.inv = function inv(items) {
  return this._inv('inv', items);
};

Framer.prototype.getData = function getData(items) {
  return this._inv('getdata', items);
};

Framer.prototype.notFound = function notFound(items) {
  return this._inv('notfound', items);
};

Framer.prototype.ping = function ping(nonce) {
  return this.packet('ping', nonce);
};

Framer.prototype.pong = function pong(nonce) {
  return this.packet('pong', nonce.slice(0, 8));
};

Framer.prototype.filterLoad = function filterLoad(bloom, update) {
  var filter = bloom.toArray();
  var before = [];
  varint(before, filter.length, 0)

  var after = new Array(9);

  // Number of hash functions
  writeU32(after, bloom.n, 0);

  // nTweak
  writeU32(after, bloom.tweak, 4);

  // nFlags
  after[8] = constants.filterFlags[update];

  var r = this.packet('filterload', before.concat(filter, after));
  return r;
};

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', []);
};

Framer.prototype.getBlocks = function getBlocks(hashes, stop) {
  var p = [];
  writeU32(p, constants.version, 0);
  var off = 4 + varint(p, hashes.length, 4);
  p.length = off + 32 * (hashes.length + 1);

  for (var i = 0; i < hashes.length; i++) {
    var hash = hashes[i];
    if (typeof hash === 'string')
      hash = utils.toArray(hash, 'hex');
    var len = utils.copy(hash, p, off);
    for (; len < 32; len++)
      p[off + len] = 0;
    off += len;
  }

  if (stop) {
    stop = utils.toArray(stop, 'hex');
    var len = utils.copy(stop, p, off);
  } else {
    var len = 0;
  }
  for (; len < 32; len++)
    p[off + len] = 0;
  assert.equal(off + len, p.length);

  return this.packet('getblocks', p);
};

Framer.tx = function tx(tx) {
  var p = [];
  var off = writeU32(p, tx.version, 0);
  off += varint(p, tx.inputs.length, off);

  for (var i = 0; i < tx.inputs.length; i++) {
    var input = tx.inputs[i];

    off += utils.copy(utils.toArray(input.out.hash, 'hex'), p, off, true);
    off += writeU32(p, input.out.index, off);

    var s = bcoin.script.encode(input.script);
    off += varint(p, s.length, off);
    off += utils.copy(s, p, off, true);

    off += writeU32(p, input.seq, off);
  }

  off += varint(p, tx.outputs.length, off);
  for (var i = 0; i < tx.outputs.length; i++) {
    var output = tx.outputs[i];

    // Put LE value
    var value = output.value.toArray().slice().reverse();
    assert(value.length <= 8);
    off += utils.copy(value, p, off, true);
    for (var j = value.length; j < 8; j++, off++)
      p[off] = 0;

    var s = bcoin.script.encode(output.script);
    off += varint(p, s.length, off);
    off += utils.copy(s, p, off, true);
  }
  off += writeU32(p, tx.lock, off);

  return p;
};
