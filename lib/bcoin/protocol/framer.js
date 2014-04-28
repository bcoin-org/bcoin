var assert = require('assert');

var bcoin = require('../../bcoin');
var constants = require('./constants');
var utils = bcoin.utils;

function Framer(peer) {
  if (!(this instanceof Framer))
    return new Framer(peer);

  this.peer = peer;
  this.network = peer.network;
}
module.exports = Framer;

Framer.prototype.header = function header(cmd, payload) {
  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  var h = new Buffer(24);

  // Magic value
  h.writeUInt32LE(constants.magic, 0, true);

  // Command
  var len = h.write(cmd, 4);
  for (var i = 4 + len; i < 4 + 12; i++)
    h[i] = 0;

  // Payload length
  h.writeUInt32LE(payload.length, 16, true);

  // Checksum
  h.writeUInt32LE(utils.checksum(payload), 20, true);

  return h;
};

Framer.prototype.packet = function packet(cmd, payload) {
  var h = this.header('version', payload);
  return Buffer.concat([ h, payload ], h.length + payload.length);
};

Framer.prototype._addr = function addr(buf, off, addr) {
};

Framer.prototype.version = function version() {
  var local = this.network.externalAddr;
  var remote = this.peer.addr;

  var p = new Buffer(86);

  // Version
  p.writeUInt32LE(constants.version, 0, true);

  // Services
  p.writeUInt32LE(constants.services.network, 4, true);
  p.writeUInt32LE(0, 8, true);

  // Timestamp
  var ts = ((+new Date) / 1000) | 0;
  p.writeUInt32LE(ts, 12, true);
  p.writeUInt32LE(0, 16, true);

  // Remote and local addresses
  this._addr(p, 20, remote);
  this._addr(p, 46, local);

  // Nonce, very dramatic
  p.writeUInt32LE(0xdeadbeef, 72, true);
  p.writeUInt32LE(0xabbadead, 76, true);

  // No user-agent
  p[80] = 0;

  // Start height
  p.writeUInt32LE(0x0, 81, true);

  // Relay
  p[85] = 0;

  return this.packet('version', p);
};
