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
const {format} = require('util');
const bio = require('bufio');
const util = require('../utils/util');
const hash256 = require('bcrypto/lib/hash256');
const sha256 = require('bcrypto/lib/sha256');
const ChaCha20 = require('bcrypto/lib/chacha20');
const Poly1305 = require('bcrypto/lib/poly1305');
const AEAD = require('bcrypto/lib/aead');
const hkdf = require('bcrypto/lib/hkdf');
const secp256k1 = require('bcrypto/lib/secp256k1');
const packets = require('./packets');
const common = require('./common');
const {encoding} = bio;
const {EncinitPacket, EncackPacket} = packets;

/*
 * Constants
 */

const HKDF_SALT = Buffer.from('bitcoinecdh', 'ascii');
const INFO_KEY1 = Buffer.from('BitcoinK1', 'ascii');
const INFO_KEY2 = Buffer.from('BitcoinK2', 'ascii');
const INFO_SID = Buffer.from('BitcoinSessionID', 'ascii');
const HIGH_WATERMARK = 1024 * (1 << 20);

/**
 * BIP151 Stream
 * Represents a BIP151 input or output stream.
 * @alias module:net.BIP151Stream
 * @property {Buffer} publicKey
 * @property {Buffer} privateKey
 * @property {Number} cipher
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

class BIP151Stream {
  /**
   * Create a BIP151 input or output stream.
   * @constructor
   * @param {Number} cipher
   */

  constructor(cipher) {
    this.cipher = BIP151.ciphers.CHACHAPOLY;
    this.privateKey = secp256k1.generatePrivateKey();
    this.publicKey = null;
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

  init(publicKey) {
    assert(Buffer.isBuffer(publicKey));

    this.publicKey = publicKey;

    const secret = secp256k1.ecdh(this.publicKey, this.privateKey).slice(1);

    const bw = bio.pool(33);

    bw.writeBytes(secret);
    bw.writeU8(this.cipher);

    const data = bw.render();
    const prk = hkdf.extract(sha256, data, HKDF_SALT);

    this.k1 = hkdf.expand(sha256, prk, INFO_KEY1, 32);
    this.k2 = hkdf.expand(sha256, prk, INFO_KEY2, 32);
    this.sid = hkdf.expand(sha256, prk, INFO_SID, 32);

    this.seq = 0;

    this.update();

    this.chacha.init(this.k1, this.iv);
    this.aead.init(this.k2, this.iv);

    this.lastRekey = util.now();
  }

  /**
   * Add buffer size to `processed`,
   * check whether we need to rekey.
   * @param {Buffer} packet
   * @returns {Boolean}
   */

  shouldRekey(packet) {
    const now = util.now();

    this.processed += packet.length;

    if (now >= this.lastRekey + 10
        || this.processed >= HIGH_WATERMARK) {
      this.lastRekey = now;
      this.processed = 0;
      return true;
    }

    return false;
  }

  /**
   * Generate new chacha keys with `key = HASH256(sid | key)`.
   * This will reinitialize the state of both ciphers.
   */

  rekey(k1, k2) {
    assert(this.sid, 'Cannot rekey before initialization.');

    if (!k1) {
      this.k1 = hash256.root(this.sid, this.k1);
      this.k2 = hash256.root(this.sid, this.k2);
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
  }

  /**
   * Increment packet sequence number and update IVs
   * (note, sequence number overflows after 2^64-1).
   * The IV will be updated without reinitializing
   * cipher state.
   */

  sequence() {
    // Wrap sequence number a la openssh.
    if (++this.seq === 0x100000000)
      this.seq = 0;

    this.update();

    // State of the ciphers is
    // unaltered aside from the iv.
    this.chacha.init(null, this.iv);
    this.aead.init(null, this.iv);
  }

  /**
   * Render the IV necessary for cipher streams.
   * @returns {Buffer}
   */

  update() {
    this.iv.writeUInt32LE(this.seq, 0, true);
    return this.iv;
  }

  /**
   * Get public key tied to private key
   * (not the same as BIP151Stream#publicKey).
   * @returns {Buffer}
   */

  getPublicKey() {
    return secp256k1.publicKeyCreate(this.privateKey, true);
  }

  /**
   * Encrypt a payload size with k1.
   * @param {Buffer} data
   * @returns {Buffer}
   */

  encryptSize(data) {
    return this.chacha.encrypt(data.slice(0, 4));
  }

  /**
   * Decrypt payload size with k1.
   * @param {Buffer} data
   * @returns {Number}
   */

  decryptSize(data) {
    this.chacha.encrypt(data);
    return data.readUInt32LE(0, true);
  }

  /**
   * Encrypt payload with AEAD (update cipher and mac).
   * @param {Buffer} data
   * @returns {Buffer} data
   */

  encrypt(data) {
    return this.aead.encrypt(data);
  }

  /**
   * Decrypt payload with AEAD (update cipher only).
   * @param {Buffer} data
   * @returns {Buffer} data
   */

  decrypt(data) {
    return this.aead.chacha20.encrypt(data);
  }

  /**
   * Authenticate payload with AEAD (update mac only).
   * @param {Buffer} data
   * @returns {Buffer} data
   */

  auth(data) {
    return this.aead.auth(data);
  }

  /**
   * Finalize AEAD and compute MAC.
   * @returns {Buffer}
   */

  final() {
    this.tag = this.aead.final();
    return this.tag;
  }

  /**
   * Verify tag against mac in constant time.
   * @param {Buffer} tag
   * @returns {Boolean}
   */

  verify(tag) {
    return Poly1305.verify(this.tag, tag);
  }
}

/**
 * BIP151
 * Represents a BIP151 input and output stream.
 * Holds state for peer communication.
 * @alias module:net.BIP151
 * @extends EventEmitter
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

class BIP151 extends EventEmitter {
  /**
   * Create a BIP151 input and output stream.
   * @constructor
   * @param {Number} cipher
   */

  constructor(cipher) {
    super();

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

  /**
   * Emit an error.
   * @param {...String} msg
   */

  error() {
    const msg = format.apply(null, arguments);
    this.emit('error', new Error(msg));
  }

  /**
   * Test whether handshake has completed.
   * @returns {Boolean}
   */

  isReady() {
    return this.initSent
      && this.ackReceived
      && this.initReceived
      && this.ackSent;
  }

  /**
   * Render an `encinit` packet. Contains the
   * input public key and cipher number.
   * @returns {Buffer}
   */

  toEncinit() {
    assert(!this.initSent, 'Cannot init twice.');
    this.initSent = true;
    return new EncinitPacket(this.input.getPublicKey(), this.input.cipher);
  }

  /**
   * Render `encack` packet. Contains the
   * output stream public key.
   * @returns {Buffer}
   */

  toEncack() {
    assert(this.output.sid, 'Cannot ack before init.');
    assert(!this.ackSent, 'Cannot ack twice.');
    this.ackSent = true;

    if (this.isReady()) {
      assert(!this.completed, 'No encack after timeout.');
      this.handshake = true;
      this.emit('handshake');
    }

    return new EncackPacket(this.output.getPublicKey());
  }

  /**
   * Render `encack` packet with an all
   * zero public key, notifying of a rekey
   * for the output stream.
   * @returns {Buffer}
   */

  toRekey() {
    assert(this.handshake, 'Cannot rekey before handshake.');
    return new EncackPacket(common.ZERO_KEY);
  }

  /**
   * Handle `encinit` from remote peer.
   * @param {Buffer}
   */

  encinit(publicKey, cipher) {
    assert(cipher === this.output.cipher, 'Cipher mismatch.');
    assert(!this.initReceived, 'Already initialized.');
    assert(!this.completed, 'No encinit after timeout.');
    this.initReceived = true;
    this.output.init(publicKey);
  }

  /**
   * Handle `encack` from remote peer.
   * @param {Buffer} data
   */

  encack(publicKey) {
    assert(this.initSent, 'Unsolicited ACK.');

    if (publicKey.equals(common.ZERO_KEY)) {
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
  }

  /**
   * Cleanup handshake job.
   * @returns {Job}
   */

  cleanup() {
    const job = this.job;

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
  }

  /**
   * Complete the timeout for handshake.
   * @param {Object} result
   */

  resolve(result) {
    const job = this.cleanup();
    job.resolve(result);
  }

  /**
   * Complete the timeout for handshake with error.
   * @param {Error} err
   */

  reject(err) {
    const job = this.cleanup();
    job.reject(err);
  }

  /**
   * Set a timeout and wait for handshake to complete.
   * @param {Number} timeout - Timeout in ms.
   * @returns {Promise}
   */

  wait(timeout) {
    return new Promise((resolve, reject) => {
      this._wait(timeout, resolve, reject);
    });
  }

  /**
   * Set a timeout and wait for handshake to complete.
   * @private
   * @param {Number} timeout
   * @param {Function} resolve
   * @param {Function} reject
   */

  _wait(timeout, resolve, reject) {
    assert(!this.handshake, 'Cannot wait for init after handshake.');

    this.job = { resolve, reject };

    this.timeout = setTimeout(() => {
      this.reject(new Error('BIP151 handshake timed out.'));
    }, timeout);

    this.onShake = this.resolve.bind(this);
    this.once('handshake', this.onShake);
  }

  /**
   * Destroy BIP151 state and streams.
   */

  destroy() {
    if (!this.job)
      return;

    this.reject(new Error('BIP151 stream was destroyed.'));
  }

  /**
   * Add buffer size to `processed`,
   * check whether we need to rekey.
   * @param {Buffer} packet
   */

  maybeRekey(packet) {
    if (!this.output.shouldRekey(packet))
      return;

    this.emit('rekey');

    if (this.bip150 && this.bip150.auth) {
      this.bip150.rekeyOutput();
      return;
    }

    this.output.rekey();
  }

  /**
   * Calculate packet size.
   * @param {String} cmd
   * @param {Buffer} body
   * @returns {Number}
   */

  packetSize(cmd, body) {
    let size = 0;
    size += 4;
    size += encoding.sizeVarString(cmd, 'ascii');
    size += 4;
    size += body.length;
    size += 16;
    return size;
  }

  /**
   * Frame plaintext payload for the output stream.
   * @param {String} cmd
   * @param {Buffer} body
   * @returns {Buffer} Ciphertext payload
   */

  packet(cmd, body) {
    const size = this.packetSize(cmd, body);
    const bw = bio.write(size);
    const payloadSize = size - 20;

    bw.writeU32(payloadSize);
    bw.writeVarString(cmd, 'ascii');
    bw.writeU32(body.length);
    bw.writeBytes(body);
    bw.seek(16);

    const msg = bw.render();
    const payload = msg.slice(4, 4 + payloadSize);

    this.maybeRekey(msg);

    this.output.encryptSize(msg);
    this.output.encrypt(payload);
    this.output.final().copy(msg, 4 + payloadSize);
    this.output.sequence();

    return msg;
  }

  /**
   * Feed ciphertext payload chunk
   * to the input stream. Potentially
   * emits a `packet` event.
   * @param {Buffer} data
   */

  feed(data) {
    this.total += data.length;
    this.pending.push(data);

    while (this.total >= this.waiting) {
      const chunk = this.read(this.waiting);
      this.parse(chunk);
    }
  }

  /**
   * Read and consume a number of bytes
   * from the buffered stream.
   * @param {Number} size
   * @returns {Buffer}
   */

  read(size) {
    assert(this.total >= size, 'Reading too much.');

    if (size === 0)
      return Buffer.alloc(0);

    const pending = this.pending[0];

    if (pending.length > size) {
      const chunk = pending.slice(0, size);
      this.pending[0] = pending.slice(size);
      this.total -= chunk.length;
      return chunk;
    }

    if (pending.length === size) {
      const chunk = this.pending.shift();
      this.total -= chunk.length;
      return chunk;
    }

    const chunk = Buffer.allocUnsafe(size);
    let off = 0;

    while (off < chunk.length) {
      const pending = this.pending[0];
      const len = pending.copy(chunk, off);
      if (len === pending.length)
        this.pending.shift();
      else
        this.pending[0] = pending.slice(len);
      off += len;
    }

    assert.strictEqual(off, chunk.length);

    this.total -= chunk.length;

    return chunk;
  }

  /**
   * Parse a ciphertext payload chunk.
   * Potentially emits a `packet` event.
   * @param {Buffer} data
   */

  parse(data) {
    if (!this.hasSize) {
      const size = this.input.decryptSize(data);

      assert(this.waiting === 4);
      assert(data.length === 4);

      // Allow 3 batched packets of max message size (12mb).
      // Not technically standard, but this protects us
      // from buffering tons of data due to either an
      // potential dos'er or a cipher state mismatch.
      // Note that 6 is the minimum size:
      // varint-cmdlen(1) str-cmd(1) u32-size(4) payload(0)
      if (size < 6 || size > BIP151.MAX_MESSAGE) {
        this.error('Bad packet size: %d.', size);
        return;
      }

      this.hasSize = true;
      this.waiting = size + 16;

      return;
    }

    const payload = data.slice(0, this.waiting - 16);
    const tag = data.slice(this.waiting - 16, this.waiting);

    this.hasSize = false;
    this.waiting = 4;

    // Authenticate payload before decrypting.
    // This ensures the cipher state isn't altered
    // if the payload integrity has been compromised.
    this.input.auth(payload);
    this.input.final();

    if (!this.input.verify(tag)) {
      this.input.sequence();
      this.error('Bad tag: %s.', tag.toString('hex'));
      return;
    }

    this.input.decrypt(payload);
    this.input.sequence();

    const br = bio.read(payload);

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
  }
}

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

/*
 * Expose
 */

module.exports = BIP151;
