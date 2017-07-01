/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const Network = require('../protocol/network');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const common = require('./common');
const packets = require('./packets');

/**
 * Protocol packet parser
 * @alias module:net.Parser
 * @constructor
 * @param {Network} network
 * @emits Parser#error
 * @emits Parser#packet
 */

function Parser(network) {
  if (!(this instanceof Parser))
    return new Parser(network);

  EventEmitter.call(this);

  this.network = Network.get(network);

  this.pending = [];
  this.total = 0;
  this.waiting = 24;
  this.header = null;
}

util.inherits(Parser, EventEmitter);

/**
 * Emit an error.
 * @private
 * @param {...String} msg
 */

Parser.prototype.error = function error() {
  let msg = util.fmt.apply(util, arguments);
  this.emit('error', new Error(msg));
};

/**
 * Feed data to the parser.
 * @param {Buffer} data
 */

Parser.prototype.feed = function feed(data) {
  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    let chunk = Buffer.allocUnsafe(this.waiting);
    let off = 0;
    let len = 0;

    while (off < chunk.length) {
      len = this.pending[0].copy(chunk, off);
      if (len === this.pending[0].length)
        this.pending.shift();
      else
        this.pending[0] = this.pending[0].slice(len);
      off += len;
    }

    assert.equal(off, chunk.length);

    this.total -= chunk.length;
    this.parse(chunk);
  }
};

/**
 * Parse a fully-buffered chunk.
 * @param {Buffer} chunk
 */

Parser.prototype.parse = function parse(data) {
  let payload, checksum;

  assert(data.length <= common.MAX_MESSAGE);

  if (!this.header) {
    this.header = this.parseHeader(data);
    return;
  }

  checksum = digest.hash256(data).readUInt32LE(0, true);

  if (checksum !== this.header.checksum) {
    this.waiting = 24;
    this.header = null;
    this.error('Invalid checksum: %s.', util.hex32(checksum));
    return;
  }

  try {
    payload = this.parsePayload(this.header.cmd, data);
  } catch (e) {
    this.waiting = 24;
    this.header = null;
    this.emit('error', e);
    return;
  }

  this.waiting = 24;
  this.header = null;

  this.emit('packet', payload);
};

/**
 * Parse buffered packet header.
 * @param {Buffer} data - Header.
 * @returns {Header}
 */

Parser.prototype.parseHeader = function parseHeader(data) {
  let i, magic, cmd, size, checksum;

  magic = data.readUInt32LE(0, true);

  if (magic !== this.network.magic) {
    this.error('Invalid magic value: %s.', util.hex32(magic));
    return null;
  }

  // Count length of the cmd
  for (i = 0; data[i + 4] !== 0 && i < 12; i++);

  if (i === 12) {
    this.error('Non NULL-terminated command.');
    return null;
  }

  cmd = data.toString('ascii', 4, 4 + i);

  size = data.readUInt32LE(16, true);

  if (size > common.MAX_MESSAGE) {
    this.waiting = 24;
    this.error('Packet length too large: %dmb.', util.mb(size));
    return null;
  }

  this.waiting = size;

  checksum = data.readUInt32LE(20, true);

  return new Header(cmd, size, checksum);
};

/**
 * Parse a payload.
 * @param {String} cmd - Packet type.
 * @param {Buffer} data - Payload.
 * @returns {Object}
 */

Parser.prototype.parsePayload = function parsePayload(cmd, data) {
  return packets.fromRaw(cmd, data);
};

/**
 * Packet Header
 * @constructor
 * @ignore
 */

function Header(cmd, size, checksum) {
  this.cmd = cmd;
  this.size = size;
  this.checksum = checksum;
}

/*
 * Expose
 */

module.exports = Parser;
