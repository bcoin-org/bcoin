/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var constants = require('../protocol/constants');
var packets = require('./packets');

/**
 * Protocol packet parser
 * @exports Parser
 * @constructor
 * @param {Object?} options
 * @emits Parser#error
 * @emits Parser#packet
 */

function Parser(options) {
  if (!(this instanceof Parser))
    return new Parser(options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.network = Network.get(options.network);
  this.bip151 = options.bip151;

  this.pending = [];
  this.total = 0;
  this.waiting = 24;
  this.header = null;

  this._init();
}

util.inherits(Parser, EventEmitter);

/**
 * Initialize. Bind to events.
 * @private
 * @param {String} str
 */

Parser.prototype._init = function _init(str) {
  var self = this;

  if (!this.bip151)
    return;

  this.bip151.on('packet', function(cmd, body) {
    var payload;
    try {
      payload = self.parsePayload(cmd, body);
    } catch (e) {
      return self.error(e);
    }
    self.emit('packet', payload);
  });
};

/**
 * Emit an error.
 * @private
 * @param {...String} msg
 */

Parser.prototype.error = function error() {
  var msg = util.fmt.apply(util, arguments);
  this.emit('error', new Error(msg));
};

/**
 * Feed data to the parser.
 * @param {Buffer} data
 */

Parser.prototype.feed = function feed(data) {
  var chunk, off, len;

  if (this.bip151 && this.bip151.handshake)
    return this.bip151.feed(data);

  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    chunk = new Buffer(this.waiting);
    off = 0;
    len = 0;

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
  var payload, checksum;

  assert(data.length <= constants.MAX_MESSAGE);

  if (!this.header) {
    this.header = this.parseHeader(data);
    return;
  }

  checksum = crypto.hash256(data).readUInt32LE(0, true);

  if (checksum !== this.header.checksum) {
    this.waiting = 24;
    this.header = null;
    return this.error('Invalid checksum: %d.', util.hex32(checksum));
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
  var i, magic, cmd, size, checksum;

  magic = data.readUInt32LE(0, true);

  if (magic !== this.network.magic)
    return this.error('Invalid magic value: %s.', util.hex32(magic));

  // Count length of the cmd
  for (i = 0; data[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this.error('Non NULL-terminated command.');

  cmd = data.toString('ascii', 4, 4 + i);

  size = data.readUInt32LE(16, true);

  if (size > constants.MAX_MESSAGE) {
    this.waiting = 24;
    return this.error('Packet length too large: %dmb.', util.mb(size));
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
 * @private
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
