/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Network = require('../protocol/network');
const digest = require('../crypto/digest');

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
 * @param {Buffer?} checksum - Precomputed checksum.
 * @returns {Buffer} Payload with header prepended.
 */

Framer.prototype.packet = function packet(cmd, payload, checksum) {
  assert(payload, 'No payload.');
  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  const msg = Buffer.allocUnsafe(24 + payload.length);

  // Magic value
  msg.writeUInt32LE(this.network.magic, 0, true);

  // Command
  msg.write(cmd, 4, 'ascii');

  for (let i = 4 + cmd.length; i < 16; i++)
    msg[i] = 0;

  // Payload length
  msg.writeUInt32LE(payload.length, 16, true);

  if (!checksum)
    checksum = digest.hash256(payload);

  // Checksum
  checksum.copy(msg, 20, 0, 4);

  payload.copy(msg, 24);

  return msg;
};

/*
 * Expose
 */

module.exports = Framer;
