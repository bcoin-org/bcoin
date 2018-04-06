/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint nonblock-statement-body-position: "off" */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const {format} = require('util');
const Network = require('../protocol/network');
const hash256 = require('bcrypto/lib/hash256');
const common = require('./common');
const packets = require('./packets');

/**
 * Protocol Message Parser
 * @alias module:net.Parser
 * @extends EventEmitter
 * @emits Parser#error
 * @emits Parser#packet
 */

class Parser extends EventEmitter {
  /**
   * Create a parser.
   * @constructor
   * @param {Network} network
   */

  constructor(network) {
    super();

    this.network = Network.get(network);

    this.pending = [];
    this.total = 0;
    this.waiting = 24;
    this.header = null;
  }

  /**
   * Emit an error.
   * @private
   * @param {...String} msg
   */

  error() {
    const msg = format.apply(null, arguments);
    this.emit('error', new Error(msg));
  }

  /**
   * Feed data to the parser.
   * @param {Buffer} data
   */

  feed(data) {
    this.total += data.length;
    this.pending.push(data);

    while (this.total >= this.waiting) {
      const chunk = Buffer.allocUnsafe(this.waiting);
      let off = 0;

      while (off < chunk.length) {
        const len = this.pending[0].copy(chunk, off);
        if (len === this.pending[0].length)
          this.pending.shift();
        else
          this.pending[0] = this.pending[0].slice(len);
        off += len;
      }

      assert.strictEqual(off, chunk.length);

      this.total -= chunk.length;
      this.parse(chunk);
    }
  }

  /**
   * Parse a fully-buffered chunk.
   * @param {Buffer} chunk
   */

  parse(data) {
    assert(data.length <= common.MAX_MESSAGE);

    if (!this.header) {
      this.header = this.parseHeader(data);
      return;
    }

    const hash = hash256.digest(data);
    const checksum = hash.readUInt32LE(0, true);

    if (checksum !== this.header.checksum) {
      this.waiting = 24;
      this.header = null;
      this.error('Invalid checksum: %s.', checksum.toString(16));
      return;
    }

    let payload;
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
  }

  /**
   * Parse buffered packet header.
   * @param {Buffer} data - Header.
   * @returns {Header}
   */

  parseHeader(data) {
    const magic = data.readUInt32LE(0, true);

    if (magic !== this.network.magic) {
      this.error('Invalid magic value: %s.', magic.toString(16));
      return null;
    }

    // Count length of the cmd.
    let i = 0;
    for (; data[i + 4] !== 0 && i < 12; i++);

    if (i === 12) {
      this.error('Non NULL-terminated command.');
      return null;
    }

    const cmd = data.toString('ascii', 4, 4 + i);

    const size = data.readUInt32LE(16, true);

    if (size > common.MAX_MESSAGE) {
      this.waiting = 24;
      this.error('Packet length too large: %d.', size);
      return null;
    }

    this.waiting = size;

    const checksum = data.readUInt32LE(20, true);

    return new Header(cmd, size, checksum);
  }

  /**
   * Parse a payload.
   * @param {String} cmd - Packet type.
   * @param {Buffer} data - Payload.
   * @returns {Object}
   */

  parsePayload(cmd, data) {
    return packets.fromRaw(cmd, data);
  }
}

/**
 * Packet Header
 * @ignore
 */

class Header {
  /**
   * Create a header.
   * @constructor
   */

  constructor(cmd, size, checksum) {
    this.cmd = cmd;
    this.size = size;
    this.checksum = checksum;
  }
}

/*
 * Expose
 */

module.exports = Parser;
