/*!
 * bip151.js - peer-to-peer communication encryption.
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0151.mediawiki
 *   https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305
 *   https://github.com/openssh/openssh-portable/blob/master/cipher-chachapoly.c
 *   https://github.com/openssh/openssh-portable/blob/master/cipher.c
 *   https://github.com/openssh/openssh-portable/blob/master/packet.c
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../env');
var utils = require('../utils/utils');
var crypto = require('../crypto/crypto');
var assert = utils.assert;
var constants = bcoin.constants;
var chachapoly = require('../crypto/chachapoly');

/*
 * Constants
 */

var HKDF_SALT = new Buffer('bitcoinecdh', 'ascii');
var INFO_KEY1 = new Buffer('BitcoinK1', 'ascii');
var INFO_KEY2 = new Buffer('BitcoinK2', 'ascii');
var INFO_SID = new Buffer('BitcoinSessionID', 'ascii');

/**
 * Represents a BIP151 input or output stream.
 * @exports BIP151Stream
 * @constructor
 * @param {Number} cipher
 * @param {Buffer?} key
 * @property {Buffer} publicKey
 * @property {Buffer} privateKey
 * @property {Number} cipher
 * @property {Buffer} prk
 * @property {Buffer} k1
 * @property {Buffer} k2
 * @property {Buffer} sid
 * @property {ChaCha20} chacha
 * @property {AEAD} aead
 * @property {Buffer} tag
 * @property {Number} seq
 * @property {Number} highWaterMark
 * @property {Number} processed
 * @property {Number} lastKey
 */

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
  this.iv = new Buffer(8);
  this.iv.fill(0);

  this.highWaterMark = 1024 * (1 << 20);
  this.processed = 0;
  this.lastRekey = 0;

  this.pending = [];
  this.total = 0;
  this.waiting = 4;
  this.hasSize = false;
}

utils.inherits(BIP151Stream, EventEmitter);

/**
 * Initialize the stream with peer's public key.
 * Computes ecdh secret and chacha keys.
 * @param {Buffer} publicKey
 */

BIP151Stream.prototype.init = function init(publicKey) {
  var p = bcoin.writer();

  this.publicKey = publicKey;
  this.secret = bcoin.ec.ecdh(this.publicKey, this.privateKey);

  p.writeBytes(this.secret);
  p.writeU8(this.cipher);

  this.prk = crypto.hkdfExtract(p.render(), HKDF_SALT, 'sha256');
  this.k1 = crypto.hkdfExpand(this.prk, INFO_KEY1, 32, 'sha256');
  this.k2 = crypto.hkdfExpand(this.prk, INFO_KEY2, 32, 'sha256');
  this.sid = crypto.hkdfExpand(this.prk, INFO_SID, 32, 'sha256');

  this.seq = 0;

  this.update();

  this.chacha.init(this.k1, this.iv);
  this.aead.init(this.k2, this.iv);

  this.lastRekey = utils.now();
};

/**
 * Add buffer size to `processed`,
 * check whether we need to rekey.
 * @param {Buffer} data
 */

BIP151Stream.prototype.maybeRekey = function maybeRekey(data) {
  var now = utils.now();

  this.processed += data.length;

  if (now >= this.lastRekey + 10
      || this.processed >= this.highWaterMark) {
    this.lastRekey = now;
    this.processed = 0;
    this.emit('rekey');
  }
};

/**
 * Generate new chacha keys with `key = HASH256(key)`.
 * This will reinitialize the state of both ciphers.
 */

BIP151Stream.prototype.rekey = function rekey(k1, k2) {
  var seed;

  assert(this.prk, 'Cannot rekey before initialization.');

  if (!k1) {
    seed = new Buffer(64);

    this.sid.copy(seed, 0);

    this.k1.copy(seed, 32);
    this.k1 = crypto.hash256(seed);

    this.k2.copy(seed, 32);
    this.k2 = crypto.hash256(seed);
  } else {
    this.k1 = k1;
    this.k2 = k2;
  }

  // All state is reinitialized
  // aside from the sequence number.
  this.chacha.init(this.k1, this.iv);
  this.aead.init(this.k2, this.iv);
};

/**
 * Increment packet sequence number and update IVs
 * (note, sequence number overflows after 2^64-1).
 * The IV will be updated without reinitializing
 * cipher state.
 */

BIP151Stream.prototype.sequence = function sequence() {
  // Wrap sequence number a la openssh.
  if (++this.seq === 0x100000000)
    this.seq = 0;

  this.update();

  // State of the ciphers is
  // unaltered aside from the iv.
  this.chacha.init(null, this.iv);
  this.aead.init(null, this.iv);
};

/**
 * Render the IV necessary for cipher streams.
 * @returns {Buffer}
 */

BIP151Stream.prototype.update = function update() {
  this.iv.writeUInt32LE(this.seq, 0, true);
  return this.iv;
};

/**
 * Get public key tied to private key
 * (not the same as BIP151Stream#privateKey).
 * @returns {Buffer}
 */

BIP151Stream.prototype.getPublicKey = function getPublicKey() {
  return bcoin.ec.publicKeyCreate(this.privateKey, true);
};

/**
 * Encrypt a payload size with k1.
 * @param {Number} size
 * @returns {Buffer}
 */

BIP151Stream.prototype.encryptSize = function encryptSize(size) {
  var data = new Buffer(4);
  data.writeUInt32LE(size, 0, true);
  return this.chacha.encrypt(data);
};

/**
 * Decrypt payload size with k1.
 * @param {Buffer} data
 * @returns {Number}
 */

BIP151Stream.prototype.decryptSize = function decryptSize(data) {
  this.chacha.encrypt(data);
  return data.readUInt32LE(0, true);
};

/**
 * Encrypt payload with AEAD (update cipher and mac).
 * @param {Buffer} data
 * @returns {Buffer} data
 */

BIP151Stream.prototype.encrypt = function encrypt(data) {
  return this.aead.encrypt(data);
};

/**
 * Decrypt payload with AEAD (update cipher only).
 * @param {Buffer} data
 * @returns {Buffer} data
 */

BIP151Stream.prototype.decrypt = function decrypt(data) {
  return this.aead.chacha20.encrypt(data);
};

/**
 * Authenticate payload with AEAD (update mac only).
 * @param {Buffer} data
 * @returns {Buffer} data
 */

BIP151Stream.prototype.auth = function auth(data) {
  return this.aead.auth(data);
};

/**
 * Finalize AEAD and compute MAC.
 * @returns {Buffer}
 */

BIP151Stream.prototype.finish = function finish() {
  this.tag = this.aead.finish();
  return this.tag;
};

/**
 * Verify tag against mac in constant time.
 * @param {Buffer} tag
 * @returns {Boolean}
 */

BIP151Stream.prototype.verify = function verify(tag) {
  return chachapoly.Poly1305.verify(this.tag, tag);
};

/**
 * Parse ciphertext data and split into chunks.
 * Potentially emits a `packet` event.
 * @param {Buffer} data
 */

BIP151Stream.prototype.feed = function feed(data) {
  var chunk;

  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    chunk = this.read(this.waiting);
    this.parse(chunk);
  }
};

/**
 * Read and consume a number of bytes
 * from the buffered stream.
 * @param {Number} size
 * @returns {Buffer}
 */

BIP151Stream.prototype.read = function read(size) {
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

/**
 * Parse a ciphertext payload chunk.
 * Potentially emits a `packet` event.
 * @param {Buffer} data
 */

BIP151Stream.prototype.parse = function parse(data) {
  var size, payload, tag, p, cmd, body;

  if (!this.hasSize) {
    size = this.decryptSize(data);

    // Allow 3 batched packets of max message size (12mb).
    // Not technically standard, but this protects us
    // from buffering tons of data due to either an
    // potential dos'er or a cipher state mismatch.
    // Note that 6 is the minimum size:
    // cmd=varint(1) string(1) length(4) data(0)
    if (size < 6 || size > constants.MAX_MESSAGE * 3) {
      this.waiting = 4;
      this.emit('error', new Error('Bad packet size.'));
      return;
    }

    this.hasSize = true;
    this.waiting = size + 16;

    return;
  }

  payload = data.slice(0, this.waiting - 16);
  tag = data.slice(this.waiting - 16, this.waiting);

  this.hasSize = false;
  this.waiting = 4;

  // Authenticate payload before decrypting.
  // This ensures the cipher state isn't altered
  // if the payload integrity has been compromised.
  this.auth(payload);
  this.finish();

  if (!this.verify(tag)) {
    this.sequence();
    this.emit('error', new Error('Bad tag.'));
    return;
  }

  this.decrypt(payload);
  this.sequence();

  p = bcoin.reader(payload);

  while (p.left()) {
    try {
      cmd = p.readVarString('ascii');
      body = p.readBytes(p.readU32());
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('packet', cmd, body);
  }
};

/**
 * Frame and encrypt a plaintext payload.
 * @param {String} cmd
 * @param {Buffer} body
 * @returns {Buffer} Ciphertext payload
 */

BIP151Stream.prototype.packet = function packet(cmd, body) {
  var p = bcoin.writer();
  var payload, packet;

  p.writeVarString(cmd, 'ascii');
  p.writeU32(body.length);
  p.writeBytes(body);

  payload = p.render();

  packet = new Buffer(4 + payload.length + 16);

  this.maybeRekey(packet);

  this.encryptSize(payload.length).copy(packet, 0);
  this.encrypt(payload).copy(packet, 4);
  this.finish().copy(packet, 4 + payload.length);
  this.sequence();

  return packet;
};

/**
 * Represents a BIP151 input and output stream.
 * Holds state for peer communication.
 * @exports BIP151
 * @constructor
 * @param {Number} cipher
 * @property {BIP151Stream} input
 * @property {BIP151Stream} output
 * @property {Boolean} initReceived
 * @property {Boolean} ackReceived
 * @property {Boolean} initSent
 * @property {Boolean} ackSent
 * @property {Object} timeout
 * @property {Function} callback
 * @property {Boolean} completed
 * @property {Boolean} handshake
 */

function BIP151(cipher) {
  if (!(this instanceof BIP151))
    return new BIP151(cipher);

  EventEmitter.call(this);

  this.input = new BIP151Stream(cipher);
  this.output = new BIP151Stream(cipher);

  this.initReceived = false;
  this.ackReceived = false;
  this.initSent = false;
  this.ackSent = false;
  this.timeout = null;
  this.callback = null;
  this.completed = false;
  this.handshake = false;

  this.bip150 = null;

  this._init();
}

utils.inherits(BIP151, EventEmitter);

/**
 * Initialize BIP151. Bind to events.
 * @private
 */

BIP151.prototype._init = function _init() {
  var self = this;

  this.output.on('rekey', function() {
    self.emit('rekey');
    if (self.bip150 && self.bip150.auth)
      self.bip150.rekeyOutput();
    else
      self.output.rekey();
  });

  this.input.on('packet', function(cmd, body) {
    self.emit('packet', cmd, body);
  });
};

/**
 * Test whether handshake has completed.
 * @returns {Boolean}
 */

BIP151.prototype.isReady = function isReady() {
  return this.initSent
    && this.ackReceived
    && this.initReceived
    && this.ackSent;
};

/**
 * Render an `encinit` packet. Contains the
 * input public key and cipher number.
 * @returns {Buffer}
 */

BIP151.prototype.toEncinit = function toEncinit(writer) {
  var p = bcoin.writer(writer);

  p.writeBytes(this.input.getPublicKey());
  p.writeU8(this.input.cipher);

  if (!writer)
    p = p.render();

  assert(!this.initSent, 'Cannot init twice.');
  this.initSent = true;

  return p;
};

/**
 * Render `encack` packet. Contains the
 * output stream public key.
 * @returns {Buffer}
 */

BIP151.prototype.toEncack = function toEncack(writer) {
  var p = bcoin.writer(writer);

  assert(this.output.prk, 'Cannot ack before init.');

  p.writeBytes(this.output.getPublicKey());

  if (!writer)
    p = p.render();

  assert(!this.ackSent, 'Cannot ack twice.');
  this.ackSent = true;

  if (this.isReady()) {
    this.handshake = true;
    this.emit('handshake');
  }

  return p;
};

/**
 * Render `encack` packet with an all
 * zero public key, notifying of a rekey
 * for the output stream.
 * @returns {Buffer}
 */

BIP151.prototype.toRekey = function toRekey(writer) {
  var p = bcoin.writer(writer);

  assert(this.handshake, 'Cannot rekey before handshake.');

  p.writeBytes(constants.ZERO_KEY);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Handle `encinit` from remote peer.
 * @param {Buffer}
 */

BIP151.prototype.encinit = function encinit(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);
  var cipher = p.readU8();

  assert(!this.initReceived, 'Already initialized.');
  this.initReceived = true;

  assert(cipher === this.output.cipher, 'Cipher mismatch.');

  this.output.init(publicKey);
};

/**
 * Handle `encack` from remote peer.
 * @param {Buffer} data
 */

BIP151.prototype.encack = function encack(data) {
  var p = bcoin.reader(data);
  var publicKey = p.readBytes(33);

  assert(this.initSent, 'Unsolicited ACK.');

  if (utils.equal(publicKey, constants.ZERO_KEY)) {
    assert(this.handshake, 'No initialization before rekey.');
    if (this.bip150 && this.bip150.auth)
      this.bip150.rekeyInput();
    else
      this.input.rekey();
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

/**
 * Complete the timeout for handshake,
 * possibly with an error.
 * @param {Error?} err
 */

BIP151.prototype.complete = function complete(err) {
  assert(!this.completed, 'Already completed.');
  assert(this.callback, 'No completion callback.');

  this.completed = true;

  clearTimeout(this.timeout);
  this.timeout = null;

  this.callback(err);
  this.callback = null;
};

/**
 * Set a timeout and wait for handshake to complete.
 * @param {Number} timeout - Timeout in ms.
 * @param {Function} callback
 */

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

/**
 * Destroy BIP151 state and streams.
 */

BIP151.prototype.destroy = function destroy() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/**
 * Feed ciphertext payload chunk
 * to the input stream. Potentially
 * emits a `packet` event.
 * @param {Buffer} data
 */

BIP151.prototype.feed = function feed(data) {
  return this.input.feed(data);
};

/**
 * Frame plaintext payload for the output stream.
 * @param {String} cmd
 * @param {Buffer} body
 * @returns {Buffer} Ciphertext payload
 */

BIP151.prototype.packet = function packet(cmd, body) {
  return this.output.packet(cmd, body);
};

/*
 * Expose
 */

module.exports = BIP151;
