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
  var h = this.header('version', payload);
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
  writeU32(p, 0xdeadbeef, 72);
  writeU32(p, 0xabbadead, 76);

  // No user-agent
  p[80] = 0;

  // Start height
  writeU32(p, packet.height, 81);

  // Relay
  p[85] = packet.relay ? 1 : 0;

  return this.packet('version', p);
};
