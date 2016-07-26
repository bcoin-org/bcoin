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

function BIP151Stream(cipher, key) {
  if (!(this instanceof BIP151Stream))
    return new BIP151Stream(cipher, key);

  EventEmitter.call(this);

  this.publicKey = null;
  this.privateKey = key || bcoin.ec.generatePrivateKey();
  this.cipher = cipher || 0;
  this.secret = null;
  this.prk = null;
  this.k1 = null;
  this.k2 = null;
  this.sid = null;

  assert(this.cipher === 0, 'Unknown cipher type.');

  this.chacha = new chachapoly.ChaCha20();
  this.aead = new chachapoly.AEAD();
  this.tag = null;
  this.seq = 0;

  this.highWaterMark = 1024 * (1 << 20);
  this.processed = 0;
  this.lastRekey = 0;

  this.pendingHeader = [];
  this.pendingHeaderTotal = 0;
  this.hasHeader = false;
  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 0;
}

utils.inherits(BIP151Stream, EventEmitter);

BIP151Stream.prototype.init = function init(publicKey) {
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

  this.lastRekey = utils.ms();
};

BIP151Stream.prototype.maybeRekey = function maybeRekey(data) {
  this.processed += data.length;
  if (this.processed >= this.highWaterMark) {
    this.processed -= this.highWaterMark;
    this.rekey();
    this.emit('rekey');
  }
};

BIP151Stream.prototype.rekey = function rekey() {
  assert(this.prk, 'Cannot rekey before initialization.');

  this.k1 = utils.hash256(this.k1);
  this.k2 = utils.hash256(this.k2);

  this.seq = 0;

  this.chacha.init(this.k1, this.iv());
  this.aead.init(this.k2, this.iv());
  this.aead.aad(this.sid);

  this.lastRekey = utils.ms();
};

BIP151Stream.prototype.sequence = function sequence() {
  this.seq++;
  this.chacha.init(null, this.iv());
  this.aead.init(null, this.iv());
};

BIP151Stream.prototype.iv = function iv() {
  var p = bcoin.writer();
  p.writeU64(this.seq);
  p.writeU32(0);
  return p.render();
};

BIP151Stream.prototype.getPublicKey = function getPublicKey() {
  return bcoin.ec.publicKeyCreate(this.privateKey, true);
};

BIP151Stream.prototype.encryptSize = function encryptSize(size) {
  var data = new Buffer(4);
  data.writeUInt32LE(size, 0, true);
  return this.chacha.encrypt(data);
};

BIP151Stream.prototype.decryptSize = function decryptSize(data) {
  data = data.slice(0, 4);
  this.chacha.encrypt(data);
  return data.readUInt32LE(0, true);
};

BIP151Stream.prototype.encrypt = function encrypt(data) {
  return this.aead.encrypt(data);
};

BIP151Stream.prototype.decrypt = function decrypt(data) {
  return this.aead.decrypt(data);
};

BIP151Stream.prototype.finish = function finish(data) {
  this.tag = this.aead.finish(data);
  return this.tag;
};

BIP151Stream.prototype.verify = function verify(tag) {
  return chachapoly.Poly1305.verify(this.tag, tag);
};

BIP151Stream.prototype.feed = function feed(data) {
  var chunk, payload, tag, p, cmd, body;

  this.maybeRekey(data);

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

      // Allow 3 batched packets of max message size.
      // Not technically standard, but this protects us
      // from buffering tons of data due to either an
      // potential dos'er or a cipher state mismatch.
      if (this.waiting - 32 > constants.MAX_MESSAGE * 3) {
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

    while (p.left()) {
      try {
        cmd = p.readVarString('ascii');
        body = p.readBytes(p.readU32());
      } catch (e) {
        this.emit('error', e);
        break;
      }

      this.emit('packet', cmd, body);
    }
  }
};

// TODO: We could batch packets here!
BIP151Stream.prototype.packet = function packet(cmd, body) {
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

  this.maybeRekey(packet);

  return packet;
};

function BIP151(cipher) {
  if (!(this instanceof BIP151))
    return new BIP151(cipher);

  EventEmitter.call(this);

  this.input = new BIP151Stream(cipher);
  this.output = null;

  this.initReceived = false;
  this.ackReceived = false;
  this.initSent = false;
  this.ackSent = false;
  this.timeout = null;
  this.callback = null;
  this.completed = false;
  this.handshake = false;

  this._init();
}

utils.inherits(BIP151, EventEmitter);

BIP151.prototype._init = function _init() {
  var self = this;

  this.input.on('rekey', function() {
    self.emit('rekey');
  });

  this.input.on('packet', function(cmd, body) {
    self.emit('packet', cmd, body);
  });
};

BIP151.prototype.isReady = function isReady() {
  return this.initSent
    && this.ackReceived
    && this.initReceived
    && this.ackSent;
};

BIP151.prototype.toEncinit = function toEncinit(writer) {
  var p = bcoin.writer(writer);

  p.writeBytes(this.input.getPublicKey());
  p.writeU8(this.input.cipher);

  if (!writer)
    p = p.render();

  this.initSent = true;

  return p;
};

BIP151.prototype.encack = function encack(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);

  assert(this.initSent, 'Unsolicited ACK.');

  if (utils.equal(publicKey, constants.ZERO_KEY)) {
    assert(this.handshake, 'No initialization before rekey.');
    this.output.rekey();
    return;
  }

  assert(!this.ackReceived, 'Already ACKed.');
  this.ackReceived = true;

  this.input.init(publicKey);

  if (this.isReady()) {
    this.handshake = true;
    this.emit('handshake');
  }
};

BIP151.prototype.encinit = function encinit(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);

  assert(!this.initReceived, 'Already initialized.');

  this.output = new BIP151Stream(p.readU8());
  this.output.init(publicKey);

  this.initReceived = true;

  return this;
};

BIP151.prototype.toEncack = function toEncack(writer) {
  var p = bcoin.writer(writer);

  assert(this.output, 'Cannot ack before init.');

  p.writeBytes(this.output.getPublicKey());

  if (!writer)
    p = p.render();

  if (!this.ackSent) {
    this.ackSent = true;
    if (this.isReady()) {
      this.handshake = true;
      this.emit('handshake');
    }
  }

  return p;
};

BIP151.prototype.toRekey = function toRekey(writer) {
  var p = bcoin.writer(writer);

  p.writeBytes(constants.ZERO_KEY);

  if (!writer)
    p = p.render();

  return p;
};

BIP151.prototype.complete = function complete(err) {
  assert(!this.completed, 'Already completed.');
  assert(this.callback, 'No completion callback.');

  this.completed = true;

  clearTimeout(this.timeout);
  this.timeout = null;

  this.callback(err);
  this.callback = null;
};

BIP151.prototype.wait = function wait(timeout, callback) {
  var self = this;

  assert(!this.handshake, 'Cannot wait for init after handshake.');

  this.callback = callback;

  this.timeout = setTimeout(function() {
    self.complete(new Error('BIP151 handshake timed out.'));
  }, timeout);

  this.once('handshake', function() {
    self.complete();
  });
};

BIP151.prototype.feed = function feed(data) {
  return this.input.feed(data);
};

BIP151.prototype.packet = function packet(cmd, body) {
  return this.output.packet(cmd, body);
};

module.exports = BIP151;
