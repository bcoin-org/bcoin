/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var utils = require('../utils/utils');
var assert = require('assert');
var BufferReader = require('../utils/reader');
var Block = require('../primitives/block');
var MTX = require('../primitives/mtx');
var TX = require('../primitives/tx');
var Coin = require('../primitives/coin');
var KeyRing = require('../primitives/keyring');
var Script = require('../script/script');
var Witness = require('../script/witness');
var HD = require('../hd/hd');
var MinerBlock = require('../miner/minerblock');

/**
 * Parser
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.waiting = 25;
  this.packet = null;
  this.pending = [];
  this.total = 0;
}

utils.inherits(Parser, EventEmitter);

Parser.prototype.feed = function feed(data) {
  var chunk;

  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    chunk = this.read(this.waiting);
    this.parse(chunk);
  }
};

Parser.prototype.read = function read(size) {
  var pending, chunk, off, len;

  assert(this.total >= size, 'Reading too much.');

  if (size === 0)
    return new Buffer(0);

  pending = this.pending[0];

  if (pending.length > size) {
    chunk = pending.slice(0, size);
    this.pending[0] = pending.slice(size);
    this.total -= chunk.length;
    return chunk;
  }

  if (pending.length === size) {
    chunk = this.pending.shift();
    this.total -= chunk.length;
    return chunk;
  }

  chunk = new Buffer(size);
  off = 0;
  len = 0;

  while (off < chunk.length) {
    pending = this.pending[0];
    len = pending.copy(chunk, off);
    if (len === pending.length)
      this.pending.shift();
    else
      this.pending[0] = pending.slice(len);
    off += len;
  }

  assert.equal(off, chunk.length);

  this.total -= chunk.length;

  return chunk;
};

Parser.prototype.parse = function parse(data) {
  var packet = this.packet;

  if (!packet) {
    try {
      packet = this.parseHeader(data);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.packet = packet;
    this.waiting = packet.size + 1;

    return;
  }

  this.waiting = 25;
  this.packet = null;

  try {
    packet.items = this.parseBody(data);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  if (data[data.length - 1] !== 0x0a) {
    this.emit('error', new Error('No trailing newline.'));
    return;
  }

  this.emit('packet', packet);
};

Parser.prototype.parseHeader = function parseHeader(data) {
  var magic, job, len, cmd, size;

  magic = data.readUInt32LE(0, true);

  if (magic !== 0xdeadbeef)
    throw new Error('Bad magic number: ' + magic.toString(16));

  job = data.readUInt32LE(4, true);

  len = data[8];
  cmd = data.toString('ascii', 9, 9 + len);

  size = data.readUInt32LE(21, true);

  return new Packet(job, cmd, size);
};

Parser.prototype.parseBody = function parseBody(data) {
  return Parser.parseItem(data);
};

Parser.parseItem = function parseItem(data) {
  var p = BufferReader(data);
  var i, count, items;

  switch (p.readU8()) {
    case 0:
      return null;
    case 1:
      return p.readVarString('utf8');
    case 2:
      return p.read32();
    case 3:
      return p.readU8() === 1;
    case 4:
      return p.readVarBytes();
    case 5:
      items = [];
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items.push(Parser.parseItem(p));
      return items;
    case 6:
      items = {};
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items[p.readVarString('utf8')] = Parser.parseItem(p);
      return items;
    case 10:
      return new bn(p.readVarBytes());
    case 40:
      return Block.fromRaw(p);
    case 41:
      return TX.fromExtended(p, true);
    case 42:
      return Coin.fromExtended(p);
    case 45:
      return MinerBlock.fromRaw(p);
    case 46:
      return MTX.fromExtended(p, true);
    case 47:
      return KeyRing.fromRaw(p);
    case 48:
      return HD.fromRaw(p.readBytes(82));
    case 49:
      return Script.fromRaw(p.readVarBytes());
    case 50:
      return Witness.fromRaw(p);
    default:
      throw new Error('Bad type.');
  }
};

/**
 * Packet
 * @constructor
 */

function Packet(job, cmd, size) {
  this.job = job;
  this.cmd = cmd;
  this.size = size;
  this.items = null;
}

/*
 * Expose
 */

module.exports = Parser;
