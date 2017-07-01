/*!
 * bip151.js - peer-to-peer communication encryption.
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0151.mediawiki
 *   https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305
 *   https://github.com/openssh/openssh-portable/blob/master/cipher-chachapoly.c
 *   https://github.com/openssh/openssh-portable/blob/master/cipher.c
 *   https://github.com/openssh/openssh-portable/blob/master/packet.c
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const util = require('../utils/util');
const co = require('../utils/co');
const digest = require('../crypto/digest');
const ChaCha20 = require('../crypto/chacha20');
const Poly1305 = require('../crypto/poly1305');
const AEAD = require('../crypto/aead');
const hkdf = require('../crypto/hkdf');
const secp256k1 = require('../crypto/secp256k1');
const packets = require('./packets');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');
const encoding = require('../utils/encoding');
const EncinitPacket = packets.EncinitPacket;
const EncackPacket = packets.EncackPacket;

/*
 * Constants
 */

const HKDF_SALT = Buffer.from('bitcoinecdh', 'ascii');
const INFO_KEY1 = Buffer.from('BitcoinK1', 'ascii');
const INFO_KEY2 = Buffer.from('BitcoinK2', 'ascii');
const INFO_SID = Buffer.from('BitcoinSessionID', 'ascii');
const HIGH_WATERMARK = 1024 * (1 << 20);

/**
 * Represents a BIP151 input or output stream.
 * @alias module:net.BIP151Stream
 * @constructor
 * @param {Number} cipher
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
 * @property {Number} processed
 * @property {Number} lastKey
 */

function BIP151Stream(cipher) {
  if (!(this instanceof BIP151Stream))
    return new BIP151Stream(cipher);

  this.cipher = BIP151.ciphers.CHACHAPOLY;
  this.privateKey = secp256k1.generatePrivateKey();
  this.publicKey = null;
  this.secret = null;
  this.prk = null;
  this.k1 = null;
  this.k2 = null;
  this.sid = null;

  if (cipher != null) {
    assert(cipher === BIP151.ciphers.CHACHAPOLY, 'Unknown cipher type.');
    this.cipher = cipher;
  }

  this.chacha = new ChaCha20();
  this.aead = new AEAD();
  this.tag = null;
  this.seq = 0;
  this.iv = Buffer.allocUnsafe(8);
  this.iv.fill(0);

  this.processed = 0;
  this.lastRekey = 0;
}

/**
 * Initialize the stream with peer's public key.
 * Computes ecdh secret and chacha keys.
 * @param {Buffer} publicKey
 */

BIP151Stream.prototype.init = function init(publicKey) {
  let bw = new StaticWriter(33);

  this.publicKey = publicKey;
  this.secret = secp256k1.ecdh(this.publicKey, this.privateKey);

  bw.writeBytes(this.secret);
  bw.writeU8(this.cipher);

  this.prk = hkdf.extract(bw.render(), HKDF_SALT, 'sha256');
  this.k1 = hkdf.expand(this.prk, INFO_KEY1, 32, 'sha256');
  this.k2 = hkdf.expand(this.prk, INFO_KEY2, 32, 'sha256');
  this.sid = hkdf.expand(this.prk, INFO_SID, 32, 'sha256');

  this.seq = 0;

  this.update();

  this.chacha.init(this.k1, this.iv);
  this.aead.init(this.k2, this.iv);

  this.lastRekey = util.now();
};

/**
 * Add buffer size to `processed`,
 * check whether we need to rekey.
 * @param {Buffer} packet
 * @returns {Boolean}
 */

BIP151Stream.prototype.shouldRekey = function shouldRekey(packet) {
  let now = util.now();

  this.processed += packet.length;

  if (now >= this.lastRekey + 10
      || this.processed >= HIGH_WATERMARK) {
    this.lastRekey = now;
    this.processed = 0;
    return true;
  }

  return false;
};

/**
 * Generate new chacha keys with `key = HASH256(sid | key)`.
 * This will reinitialize the state of both ciphers.
 */

BIP151Stream.prototype.rekey = function rekey(k1, k2) {
  assert(this.prk, 'Cannot rekey before initialization.');

  if (!k1) {
    let seed = Buffer.allocUnsafe(64);

    this.sid.copy(seed, 0);

    this.k1.copy(seed, 32);
    this.k1 = digest.hash256(seed);

    this.k2.copy(seed, 32);
    this.k2 = digest.hash256(seed);
  } else {
    this.k1 = k1;
    this.k2 = k2;
  }

  assert(this.k1);
  assert(this.k2);

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
 * (not the same as BIP151Stream#publicKey).
 * @returns {Buffer}
 */

BIP151Stream.prototype.getPublicKey = function getPublicKey() {
  return secp256k1.publicKeyCreate(this.privateKey, true);
};

/**
 * Encrypt a payload size with k1.
 * @param {Buffer} data
 * @returns {Buffer}
 */

BIP151Stream.prototype.encryptSize = function encryptSize(data) {
  return this.chacha.encrypt(data.slice(0, 4));
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
  return Poly1305.verify(this.tag, tag);
};

/**
 * Represents a BIP151 input and output stream.
 * Holds state for peer communication.
 * @alias module:net.BIP151
 * @constructor
 * @param {Number} cipher
 * @property {BIP151Stream} input
 * @property {BIP151Stream} output
 * @property {Boolean} initReceived
 * @property {Boolean} ackReceived
 * @property {Boolean} initSent
 * @property {Boolean} ackSent
 * @property {Object} timeout
 * @property {Job} job
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
  this.completed = false;
  this.handshake = false;

  this.pending = [];
  this.total = 0;
  this.waiting = 4;
  this.hasSize = false;

  this.timeout = null;
  this.job = null;
  this.onShake = null;

  this.bip150 = null;
}

util.inherits(BIP151, EventEmitter);

/**
 * Cipher list.
 * @enum {Number}
 */

BIP151.ciphers = {
  CHACHAPOLY: 0
};

/**
 * Max message size.
 * @const {Number}
 * @default
 */

BIP151.MAX_MESSAGE = 12 * 1000 * 1000;

/**
 * Emit an error.
 * @param {...String} msg
 */

BIP151.prototype.error = function error() {
  let msg = util.fmt.apply(util, arguments);
  this.emit('error', new Error(msg));
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

BIP151.prototype.toEncinit = function toEncinit() {
  assert(!this.initSent, 'Cannot init twice.');
  this.initSent = true;
  return new EncinitPacket(this.input.getPublicKey(), this.input.cipher);
};

/**
 * Render `encack` packet. Contains the
 * output stream public key.
 * @returns {Buffer}
 */

BIP151.prototype.toEncack = function toEncack() {
  assert(this.output.prk, 'Cannot ack before init.');
  assert(!this.ackSent, 'Cannot ack twice.');
  this.ackSent = true;

  if (this.isReady()) {
    assert(!this.completed, 'No encack after timeout.');
    this.handshake = true;
    this.emit('handshake');
  }

  return new EncackPacket(this.output.getPublicKey());
};

/**
 * Render `encack` packet with an all
 * zero public key, notifying of a rekey
 * for the output stream.
 * @returns {Buffer}
 */

BIP151.prototype.toRekey = function toRekey() {
  assert(this.handshake, 'Cannot rekey before handshake.');
  return new EncackPacket(encoding.ZERO_KEY);
};

/**
 * Handle `encinit` from remote peer.
 * @param {Buffer}
 */

BIP151.prototype.encinit = function encinit(publicKey, cipher) {
  assert(cipher === this.output.cipher, 'Cipher mismatch.');
  assert(!this.initReceived, 'Already initialized.');
  assert(!this.completed, 'No encinit after timeout.');
  this.initReceived = true;
  this.output.init(publicKey);
};

/**
 * Handle `encack` from remote peer.
 * @param {Buffer} data
 */

BIP151.prototype.encack = function encack(publicKey) {
  assert(this.initSent, 'Unsolicited ACK.');

  if (publicKey.equals(encoding.ZERO_KEY)) {
    assert(this.handshake, 'No initialization before rekey.');

    if (this.bip150 && this.bip150.auth) {
      this.bip150.rekeyInput();
      return;
    }

    this.input.rekey();

    return;
  }

  assert(!this.ackReceived, 'Already ACKed.');
  assert(!this.completed, 'No encack after timeout.');
  this.ackReceived = true;

  this.input.init(publicKey);

  if (this.isReady()) {
    this.handshake = true;
    this.emit('handshake');
  }
};

/**
 * Cleanup handshake job.
 * @returns {Job}
 */

BIP151.prototype.cleanup = function cleanup() {
  let job = this.job;

  assert(!this.completed, 'Already completed.');
  assert(job, 'No completion job.');

  this.completed = true;
  this.job = null;

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  if (this.onShake) {
    this.removeListener('handshake', this.onShake);
    this.onShake = null;
  }

  return job;
};

/**
 * Complete the timeout for handshake.
 * @param {Object} result
 */

BIP151.prototype.resolve = function resolve(result) {
  let job = this.cleanup();
  job.resolve(result);
};

/**
 * Complete the timeout for handshake with error.
 * @param {Error} err
 */

BIP151.prototype.reject = function reject(err) {
  let job = this.cleanup();
  job.reject(err);
};

/**
 * Set a timeout and wait for handshake to complete.
 * @param {Number} timeout - Timeout in ms.
 * @returns {Promise}
 */

BIP151.prototype.wait = function wait(timeout) {
  return new Promise((resolve, reject) => {
    this._wait(timeout, resolve, reject);
  });
};

/**
 * Set a timeout and wait for handshake to complete.
 * @private
 * @param {Number} timeout
 * @param {Function} resolve
 * @param {Function} reject
 */

BIP151.prototype._wait = function wait(timeout, resolve, reject) {
  assert(!this.handshake, 'Cannot wait for init after handshake.');

  this.job = co.job(resolve, reject);

  this.timeout = setTimeout(() => {
    this.reject(new Error('BIP151 handshake timed out.'));
  }, timeout);

  this.onShake = this.resolve.bind(this);
  this.once('handshake', this.onShake);
};

/**
 * Destroy BIP151 state and streams.
 */

BIP151.prototype.destroy = function destroy() {
  if (!this.job)
    return;

  this.reject(new Error('BIP151 stream was destroyed.'));
};

/**
 * Add buffer size to `processed`,
 * check whether we need to rekey.
 * @param {Buffer} packet
 */

BIP151.prototype.maybeRekey = function maybeRekey(packet) {
  if (!this.output.shouldRekey(packet))
    return;

  this.emit('rekey');

  if (this.bip150 && this.bip150.auth) {
    this.bip150.rekeyOutput();
    return;
  }

  this.output.rekey();
};

/**
 * Calculate packet size.
 * @param {String} cmd
 * @param {Buffer} body
 * @returns {Number}
 */

BIP151.prototype.packetSize = function packetSize(cmd, body) {
  let size = 0;
  size += 4;
  size += encoding.sizeVarString(cmd, 'ascii');
  size += 4;
  size += body.length;
  size += 16;
  return size;
};

/**
 * Frame plaintext payload for the output stream.
 * @param {String} cmd
 * @param {Buffer} body
 * @returns {Buffer} Ciphertext payload
 */

BIP151.prototype.packet = function _packet(cmd, body) {
  let size = this.packetSize(cmd, body);
  let bw = new StaticWriter(size);
  let payloadSize = size - 20;
  let packet, payload;

  bw.writeU32(payloadSize);
  bw.writeVarString(cmd, 'ascii');
  bw.writeU32(body.length);
  bw.writeBytes(body);
  bw.seek(16);

  packet = bw.render();
  payload = packet.slice(4, 4 + payloadSize);

  this.maybeRekey(packet);

  this.output.encryptSize(packet);
  this.output.encrypt(payload);
  this.output.finish().copy(packet, 4 + payloadSize);
  this.output.sequence();

  return packet;
};

/**
 * Feed ciphertext payload chunk
 * to the input stream. Potentially
 * emits a `packet` event.
 * @param {Buffer} data
 */

BIP151.prototype.feed = function feed(data) {
  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    let chunk = this.read(this.waiting);
    this.parse(chunk);
  }
};

/**
 * Read and consume a number of bytes
 * from the buffered stream.
 * @param {Number} size
 * @returns {Buffer}
 */

BIP151.prototype.read = function read(size) {
  let pending, chunk, off, len;

  assert(this.total >= size, 'Reading too much.');

  if (size === 0)
    return Buffer.alloc(0);

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

  chunk = Buffer.allocUnsafe(size);
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

BIP151.prototype.parse = function parse(data) {
  let payload, tag, br;

  if (!this.hasSize) {
    let size = this.input.decryptSize(data);

    assert(this.waiting === 4);
    assert(data.length === 4);

    // Allow 3 batched packets of max message size (12mb).
    // Not technically standard, but this protects us
    // from buffering tons of data due to either an
    // potential dos'er or a cipher state mismatch.
    // Note that 6 is the minimum size:
    // varint-cmdlen(1) str-cmd(1) u32-size(4) payload(0)
    if (size < 6 || size > BIP151.MAX_MESSAGE) {
      this.error('Bad packet size: %d.', util.mb(size));
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
  this.input.auth(payload);
  this.input.finish();

  if (!this.input.verify(tag)) {
    this.input.sequence();
    this.error('Bad tag: %s.', tag.toString('hex'));
    return;
  }

  this.input.decrypt(payload);
  this.input.sequence();

  br = new BufferReader(payload);

  while (br.left()) {
    let cmd, body;

    try {
      cmd = br.readVarString('ascii');
      body = br.readBytes(br.readU32());
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('packet', cmd, body);
  }
};

/*
 * Expose
 */

module.exports = BIP151;
