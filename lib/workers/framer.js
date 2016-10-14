/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var BN = require('bn.js');
var utils = require('../utils/utils');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
var MTX = require('../primitives/mtx');
var TX = require('../primitives/tx');
var KeyRing = require('../primitives/keyring');
var Script = require('../script/script');
var Witness = require('../script/witness');

/**
 * Framer
 * @constructor
 */

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();

  EventEmitter.call(this);
}

utils.inherits(Framer, EventEmitter);

Framer.prototype.packet = function packet(job, cmd, items) {
  var payload = this.body(items);
  var packet = new Buffer(25 + payload.length + 1);

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  packet.writeUInt32LE(0xdeadbeef, 0, true);
  packet.writeUInt32LE(job, 4, true);
  packet.writeUInt8(cmd.length, 8, true);
  packet.write(cmd, 9, 'ascii');
  packet.writeUInt32LE(payload.length, 21, true);
  payload.copy(packet, 25);
  packet[packet.length - 1] = 0x0a;

  return packet;
};

Framer.prototype.body = function body(items) {
  return Framer.item(items);
};

Framer.item = function _item(item, writer) {
  var p = BufferWriter(writer);
  var i, keys;

  switch (typeof item) {
    case 'string':
      p.writeU8(1);
      p.writeVarString(item, 'utf8');
      break;
    case 'number':
      if (item > 0x7fffffff) {
        p.writeU8(3);
        p.writeU32(item);
      } else {
        p.writeU8(2);
        p.write32(item);
      }
      break;
    case 'boolean':
      p.writeU8(4);
      p.writeU8(item ? 1 : 0);
      break;
    case 'object':
    case 'undefined':
      if (item == null) {
        p.writeU8(0);
        break;
      }
      if (item instanceof Script) {
        p.writeU8(40);
        p.writeVarBytes(item.toRaw());
      } else if (item instanceof Witness) {
        p.writeU8(41);
        item.toRaw(p);
      } else if (item instanceof MTX) {
        p.writeU8(42);
        item.toExtended(true, p);
      } else if (item instanceof TX) {
        p.writeU8(43);
        item.toExtended(true, p);
      } else if (item instanceof KeyRing) {
        p.writeU8(44);
        item.toRaw(p);
      } else if (BN.isBN(item)) {
        p.writeU8(10);
        p.writeVarBytes(item.toArrayLike(Buffer));
      } else if (Buffer.isBuffer(item)) {
        p.writeU8(5);
        p.writeVarBytes(item);
      } else if (Array.isArray(item)) {
        p.writeU8(6);
        p.writeVarint(item.length);
        for (i = 0; i < item.length; i++)
          Framer.item(item[i], p);
      } else {
        keys = Object.keys(item);
        p.writeU8(7);
        p.writeVarint(keys.length);
        for (i = 0; i < keys.length; i++) {
          p.writeVarString(keys[i], 'utf8');
          Framer.item(item[keys[i]], p);
        }
      }
      break;
    default:
      throw new Error('Bad type.');
  }

  if (!writer)
    p = p.render();

  return p;
};

/*
 * Expose
 */

module.exports = Framer;
