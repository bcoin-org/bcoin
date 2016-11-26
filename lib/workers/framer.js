/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var BN = require('bn.js');
var util = require('../utils/util');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
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

util.inherits(Framer, EventEmitter);

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
  var bw = BufferWriter(writer);
  var i, keys;

  switch (typeof item) {
    case 'string':
      bw.writeU8(1);
      bw.writeVarString(item, 'utf8');
      break;
    case 'number':
      if (item > 0x7fffffff) {
        bw.writeU8(3);
        bw.writeU32(item);
      } else {
        bw.writeU8(2);
        bw.write32(item);
      }
      break;
    case 'boolean':
      bw.writeU8(4);
      bw.writeU8(item ? 1 : 0);
      break;
    case 'object':
    case 'undefined':
      if (item == null) {
        bw.writeU8(0);
        break;
      }
      if (item instanceof Script) {
        bw.writeU8(40);
        bw.writeVarBytes(item.toRaw());
      } else if (item instanceof Witness) {
        bw.writeU8(41);
        item.toRaw(bw);
      } else if (isMTX(item)) {
        bw.writeU8(42);
        item.toExtended(true, bw);
      } else if (isTX(item)) {
        bw.writeU8(43);
        item.toExtended(true, bw);
      } else if (item instanceof KeyRing) {
        bw.writeU8(44);
        item.toRaw(bw);
      } else if (BN.isBN(item)) {
        bw.writeU8(10);
        bw.writeVarBytes(item.toArrayLike(Buffer));
      } else if (Buffer.isBuffer(item)) {
        bw.writeU8(5);
        bw.writeVarBytes(item);
      } else if (Array.isArray(item)) {
        bw.writeU8(6);
        bw.writeVarint(item.length);
        for (i = 0; i < item.length; i++)
          Framer.item(item[i], bw);
      } else {
        keys = Object.keys(item);
        bw.writeU8(7);
        bw.writeVarint(keys.length);
        for (i = 0; i < keys.length; i++) {
          bw.writeVarString(keys[i], 'utf8');
          Framer.item(item[keys[i]], bw);
        }
      }
      break;
    default:
      throw new Error('Bad type.');
  }

  if (!writer)
    bw = bw.render();

  return bw;
};

/*
 * Helpers
 */

function isTX(tx) {
  return tx && tx.witnessHash && tx.mutable === false;
}

function isMTX(tx) {
  return tx && tx.witnessHash && tx.mutable === true;
}

/*
 * Expose
 */

module.exports = Framer;
