/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
var assert = utils.assert;
var constants = require('../protocol/constants');
var BufferReader = require('../utils/reader');
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

  this.network = bcoin.network.get(options.network);
  this.bip151 = options.bip151;

  this.pending = [];
  this.total = 0;
  this.waiting = 24;
  this.packet = null;

  this._init();
}

utils.inherits(Parser, EventEmitter);

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
    var packet = new Packet(cmd, body.length);
    try {
      packet.payload = self.parsePayload(cmd, body);
    } catch (e) {
      return self._error(e);
    }
    self.emit('packet', packet);
  });
};

/**
 * Emit an error.
 * @private
 * @param {String} str
 */

Parser.prototype._error = function _error(str) {
  this.emit('error', new Error(str));
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

Parser.prototype.parse = function parse(chunk) {
  var checksum;

  if (chunk.length > constants.MAX_MESSAGE) {
    this.waiting = 24;
    this.packet = null;
    return this._error('Packet too large: %dmb.', utils.mb(chunk.length));
  }

  if (!this.packet) {
    this.packet = this.parseHeader(chunk);
    return;
  }

  this.packet.payload = chunk;

  checksum = utils.checksum(this.packet.payload).readUInt32LE(0, true);

  if (checksum !== this.packet.checksum) {
    this.waiting = 24;
    this.packet = null;
    return this._error('Invalid checksum');
  }

  try {
    this.packet.payload = this.parsePayload(this.packet.cmd, this.packet.payload);
  } catch (e) {
    this.emit('error', e);
    this.waiting = 24;
    this.packet = null;
    return;
  }

  this.emit('packet', this.packet);
  this.waiting = 24;
  this.packet = null;
};

/**
 * Parse buffered packet header.
 * @param {Buffer} h - Header.
 * @returns {Object} Packet header in the form
 * of `{cmd:String, length:Number, checksum:Number}`.
 */

Parser.prototype.parseHeader = function parseHeader(h) {
  var i, magic, cmd, chk;

  magic = h.readUInt32LE(0, true);

  if (magic !== this.network.magic)
    return this._error('Invalid magic value: ' + magic.toString(16));

  // Count length of the cmd
  for (i = 0; h[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  cmd = h.toString('ascii', 4, 4 + i);

  this.waiting = h.readUInt32LE(16, true);

  if (this.waiting > constants.MAX_MESSAGE) {
    this.waiting = 24;
    return this._error('Packet length too large: %dmb', utils.mb(this.waiting));
  }

  chk = h.readUInt32LE(20, true);

  return new Packet(cmd, this.waiting, chk);
};

/**
 * Parse a payload.
 * @param {String} cmd - Packet type.
 * @param {Buffer} data - Payload.
 * @returns {Object}
 */

Parser.prototype.parsePayload = function parsePayload(cmd, data) {
  switch (cmd) {
    case 'version':
      return packets.VersionPacket.fromRaw(data);
    case 'verack':
      return null;
    case 'ping':
      return parsePing(data);
    case 'pong':
      return parsePing(data);
    case 'alert':
      return packets.AlertPacket.fromRaw(data);
    case 'getaddr':
      return null;
    case 'addr':
      return parseAddr(data);
    case 'inv':
      return parseInv(data);
    case 'getdata':
      return parseInv(data);
    case 'notfound':
      return parseInv(data);
    case 'getblocks':
      return packets.GetBlocksPacket.fromRaw(data);
    case 'getheaders':
      return packets.GetBlocksPacket.fromRaw(data);
    case 'headers':
      return parseHeaders(data);
    case 'sendheaders':
      return null;
    case 'block':
      return bcoin.memblock.fromRaw(data);
    case 'tx':
      return bcoin.tx.fromRaw(data);
    case 'reject':
      return packets.RejectPacket.fromRaw(data);
    case 'mempool':
      return null;
    case 'filterload':
      return bcoin.bloom.fromRaw(data);
    case 'filteradd':
      return parseFilterAdd(data);
    case 'filterclear':
      return null;
    case 'merkleblock':
      return bcoin.merkleblock.fromRaw(data);
    case 'getutxos':
      return packets.GetUTXOsPacket.fromRaw(data);
    case 'utxos':
      return packets.UTXOsPacket.fromRaw(data);
    case 'havewitness':
      return null;
    case 'feefilter':
      return parseFeeFilter(data);
    case 'sendcmpct':
      return bcoin.bip152.SendCompact.fromRaw(data);
    case 'cmpctblock':
      return bcoin.bip152.CompactBlock.fromRaw(data);
    case 'getblocktxn':
      return bcoin.bip152.TXRequest.fromRaw(data);
    case 'blocktxn':
      return bcoin.bip152.TXResponse.fromRaw(data);
    case 'encinit':
      assert(data.length >= 34);
      return data;
    case 'encack':
      assert(data.length >= 33);
      return data;
    case 'authchallenge':
      assert(data.length >= 32);
      return data;
    case 'authreply':
      assert(data.length >= 64);
      return data;
    case 'authpropose':
      assert(data.length >= 32);
      return data;
    default:
      return data;
  }
};

/*
 * Helpers
 */

function parsePing(data) {
  var p = new BufferReader(data);
  return p.readU64();
}

function parseInv(data) {
  var p = new BufferReader(data);
  var items = [];
  var i, count;

  count = p.readVarint();

  assert(count <= 50000, 'Item count too high.');

  for (i = 0; i < count; i++)
    items.push(bcoin.invitem.fromRaw(p));

  return items;
}

function parseHeaders(data) {
  var p = new BufferReader(data);
  var headers = [];
  var i, count;

  count = p.readVarint();

  for (i = 0; i < count; i++)
    headers.push(bcoin.headers.fromRaw(p));

  return headers;
}

function parseAddr(data) {
  var p = new BufferReader(data);
  var addrs = [];
  var i, count;

  count = p.readVarint();

  assert(count <= 10000, 'Too many addresses.');

  for (i = 0; i < count; i++)
    addrs.push(packets.NetworkAddress.fromRaw(p, true));

  return addrs;
}

function parseFeeFilter(data) {
  var p = new BufferReader(data);
  return p.read64N();
}

function parseFilterAdd(data) {
  var p = new BufferReader(data);
  return p.readVarBytes();
}

/**
 * Packet
 * @constructor
 * @private
 */

function Packet(cmd, size, checksum) {
  this.cmd = cmd;
  this.size = size;
  this.checksum = checksum;
  this.payload = null;
}

/*
 * Expose
 */

module.exports = Parser;
