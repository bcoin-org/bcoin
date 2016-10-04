/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var crypto = require('../crypto/crypto');
var assert = require('assert');

/**
 * Protocol packet framer
 * @exports Framer
 * @constructor
 * @param {Object} options
 */

function Framer(options) {
  if (!(this instanceof Framer))
    return new Framer(options);

  if (!options)
    options = {};

  this.options = options;

  this.network = Network.get(options.network);
  this.bip151 = options.bip151;
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

  if (this.bip151 && this.bip151.handshake)
    return this.bip151.packet(cmd, payload);

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
