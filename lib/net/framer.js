/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var Network = require('../protocol/network');
var crypto = require('../crypto/crypto');

/**
 * Protocol packet framer
 * @alias module:net.Framer
 * @constructor
 * @param {Network} network
 */

function Framer(network) {
  if (!(this instanceof Framer))
    return new Framer(network);

  this.network = Network.get(network);
}

/**
 * Frame a payload with a header.
 * @param {String} cmd - Packet type.
 * @param {Buffer} payload
 * @returns {Buffer} Payload with header prepended.
 */

Framer.prototype.packet = function packet(cmd, payload, checksum) {
  var i, packet;

  assert(payload, 'No payload.');

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  packet = new Buffer(24 + payload.length);

  // Magic value
  packet.writeUInt32LE(this.network.magic, 0, true);

  // Command
  packet.write(cmd, 4, 'ascii');

  for (i = 4 + cmd.length; i < 16; i++)
    packet[i] = 0;

  // Payload length
  packet.writeUInt32LE(payload.length, 16, true);

  if (!checksum)
    checksum = crypto.hash256(payload);

  // Checksum
  checksum.copy(packet, 20, 0, 4);

  payload.copy(packet, 24);

  return packet;
};

/*
 * Expose
 */

module.exports = Framer;
