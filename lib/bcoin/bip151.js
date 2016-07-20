/*!
 * bip151.js - peer-to-peer communication encryption.
 * See: https://github.com/bitcoin/bips/blob/master/bip-0151.mediawiki
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var chachapoly = require('./chachapoly');

var HKDF_SALT = new Buffer('bitcoinechd' /* ecHd (sic?) */, 'ascii');
var INFO_KEY1 = new Buffer('BitcoinK1', 'ascii');
var INFO_KEY2 = new Buffer('BitcoinK2', 'ascii');
var INFO_SID = new Buffer('BitcoinSessionID', 'ascii');

function BIP151(cipher, key) {
  if (!(this instanceof BIP151))
    return new BIP151(cipher, key);

  EventEmitter.call(this);

  this.publicKey = null;
  this.privateKey = key || bcoin.ec.generatePrivateKey();
  this.cipher = cipher || 0;
  this.secret = null;
  this.k1 = null;
  this.k2 = null;
  this.sid = null;
  this.chacha = new chachapoly.ChaCha20();
  this.aead = new chachapoly.AEAD();
  this.prk = null;
  this.tag = null;
  this.seq = 0;

  this.pendingHeader = [];
  this.pendingHeaderTotal = 0;
  this.hasHeader = false;
  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 0;
}

utils.inherits(BIP151, EventEmitter);

BIP151.prototype.init = function init(publicKey) {
  var p = bcoin.writer();

  this.publicKey = publicKey;
  this.secret = bcoin.ec.ecdh(this.publicKey, this.privateKey);

  p.writeBytes(this.secret);
  p.writeU8(this.cipher);

  this.prk = utils.hkdfExtract(p.render(), HKDF_SALT, 'sha256');
  this.k1 = utils.hkdfExpand(this.prk, INFO_KEY1, 32, 'sha256');
  this.k2 = utils.hkdfExpand(this.prk, INFO_KEY2, 32, 'sha256');
  this.sid = utils.hkdfExpand(this.prk, INFO_SID, 32, 'sha256');

  this.seq = 0;

  this.chacha.init(this.k1, this.iv());
  this.aead.init(this.k2, this.iv());
  this.aead.aad(this.sid);
};

BIP151.prototype.rekey = function rekey() {
  assert(this.prk, 'Cannot rekey before initialization.');
  this.k1 = utils.hash256(this.k1);
  this.k2 = utils.hash256(this.k2);
  this.seq = 0;
  this.chacha.init(this.k1, this.iv());
  this.aead.init(this.k2, this.iv());
  this.aead.aad(this.sid);
};

BIP151.prototype.sequence = function sequence() {
  this.seq++;
  this.chacha.init(this.k1, this.iv());
  this.aead.init(this.k2, this.iv());
  this.aead.aad(this.sid);
};

BIP151.prototype.iv = function iv() {
  var p = bcoin.writer();
  p.writeU64(this.seq);
  p.writeU32(0);
  return p.render();
};

BIP151.prototype.getPublicKey = function getPublicKey() {
  return bcoin.ec.publicKeyCreate(this.privateKey, true);
};

BIP151.prototype.encryptSize = function encryptSize(size) {
  var data = new Buffer(4);
  data.writeUInt32LE(size, 0, true);
  return this.chacha.encrypt(data);
};

BIP151.prototype.decryptSize = function decryptSize(data) {
  data = data.slice(0, 4);
  this.chacha.encrypt(data);
  return data.readUInt32LE(0, true);
};

BIP151.prototype.encrypt = function encrypt(data) {
  return this.aead.encrypt(data);
};

BIP151.prototype.decrypt = function decrypt(data) {
  return this.aead.decrypt(data);
};

BIP151.prototype.finish = function finish(data) {
  this.tag = this.aead.finish(data);
  return this.tag;
};

BIP151.prototype.verify = function verify(tag) {
  return chachapoly.Poly1305.verify(this.tag, tag);
};

BIP151.prototype.toEncinit = function toEncinit(writer) {
  var p = bcoin.writer(writer);

  p.writeBytes(this.getPublicKey());
  p.writeU8(this.cipher);

  if (!writer)
    p = p.render();

  return p;
};

BIP151.prototype.fromEncinit = function fromEncinit(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);
  this.cipher = p.readU8();
  this.init(publicKey);
  return this;
};

BIP151.fromEncinit = function fromEncinit(data) {
  return new BIP151().fromEncinit(data);
};

BIP151.prototype.toEncack = function toEncack(writer) {
  var p = bcoin.writer(writer);

  p.writeBytes(this.getPublicKey());

  if (!writer)
    p = p.render();

  return p;
};

BIP151.prototype.encack = function encack(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);
  var i;

  for (i = 0; i < publicKey.length; i++) {
    if (publicKey[i] !== 0)
      break;
  }

  if (i === publicKey.length) {
    this.rekey();
    return;
  }

  this.init(publicKey);
};

BIP151.prototype.feed = function feed(data) {
  var chunk, payload, tag, p, cmd, body;

  while (data) {
    if (!this.hasHeader) {
      this.pendingHeaderTotal += data.length;
      this.pendingHeader.push(data);
      data = null;

      if (this.pendingHeaderTotal < 4)
        break;

      chunk = Buffer.concat(this.pendingHeader);

      this.pendingHeaderTotal = 0;
      this.pendingHeader.length = 0;

      this.waiting = this.decryptSize(chunk) + 16;

      if (this.waiting - 32 > constants.MAX_MESSAGE) {
        this.waiting = 0;
        this.emit('error', new Error('Packet too large.'));
        continue;
      }

      this.hasHeader = true;

      data = chunk.slice(4);

      if (data.length === 0)
        break;
    }

    this.pendingTotal += data.length;
    this.pending.push(data);
    data = null;

    if (this.pendingTotal < this.waiting)
      break;

    chunk = Buffer.concat(this.pending);
    payload = chunk.slice(0, this.waiting - 16);
    tag = chunk.slice(this.waiting - 16, this.waiting);
    data = chunk.slice(this.waiting);

    if (data.length === 0)
      data = null;

    this.decrypt(payload);
    this.finish();
    this.sequence();

    this.pendingTotal = 0;
    this.pending.length = 0;
    this.hasHeader = false;
    this.waiting = 0;

    if (!this.verify(tag)) {
      this.emit('error', new Error('Bad tag.'));
      continue;
    }

    p = bcoin.reader(payload, true);
    cmd = p.readVarString('ascii');
    body = p.readBytes(p.readU32());

    this.emit('packet', cmd, body);
  }
};

BIP151.prototype.frame = function frame(cmd, body) {
  var p = bcoin.writer();
  var payload, packet;

  p.writeVarString(cmd, 'ascii');
  p.writeU32(body.length);
  p.writeBytes(body);

  payload = p.render();

  packet = new Buffer(4 + payload.length + 16);

  this.encryptSize(payload.length).copy(packet, 0);
  this.encrypt(payload).copy(packet, 4);
  this.finish().copy(packet, 4 + payload.length);
  this.sequence();

  return packet;
};
