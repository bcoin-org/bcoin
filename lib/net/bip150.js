/*!
 * bip150.js - peer auth.
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0150.mediawiki
 */

'use strict';

const assert = require('assert');
const path = require('path');
const EventEmitter = require('events');
const bio = require('bufio');
const fs = require('bfile');
const dns = require('bdns');
const IP = require('binet');
const Logger = require('blgr');
const {base58} = require('bstring');
const ccmp = require('bcrypto/lib/ccmp');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const consensus = require('../protocol/consensus');
const packets = require('./packets');
const common = require('./common');

/**
 * BIP150
 * Represents a BIP150 input/output stream.
 * @alias module:net.BIP150
 * @extends EventEmitter
 * @property {BIP151} bip151
 * @property {BIP151Stream} input
 * @property {BIP151Stream} output
 * @property {String} hostname
 * @property {Boolean} outbound
 * @property {AuthDB} db
 * @property {Buffer} privateKey
 * @property {Buffer} publicKey
 * @property {Buffer} peerIdentity
 * @property {Boolean} challengeReceived
 * @property {Boolean} replyReceived
 * @property {Boolean} proposeReceived
 * @property {Boolean} challengeSent
 * @property {Boolean} auth
 * @property {Boolean} completed
 */

class BIP150 extends EventEmitter {
  /**
   * Create a BIP150 input/output stream.
   * @constructor
   * @param {BIP151} bip151
   * @param {String} host
   * @param {Boolean} outbound
   * @param {AuthDB} db
   * @param {Buffer} key - Identity key.
   */

  constructor(bip151, host, outbound, db, key) {
    super();

    assert(bip151, 'BIP150 requires BIP151.');
    assert(typeof host === 'string', 'Hostname required.');
    assert(typeof outbound === 'boolean', 'Outbound flag required.');
    assert(db instanceof AuthDB, 'Auth DB required.');
    assert(Buffer.isBuffer(key), 'Identity key required.');

    this.bip151 = bip151;
    this.input = bip151.input;
    this.output = bip151.output;
    this.hostname = host;
    this.outbound = outbound;
    this.db = db;
    this.privateKey = key;
    this.publicKey = secp256k1.publicKeyCreate(key, true);

    this.peerIdentity = null;
    this.challengeReceived = false;
    this.replyReceived = false;
    this.proposeReceived = false;
    this.challengeSent = false;
    this.auth = false;
    this.completed = false;
    this.job = null;
    this.timeout = null;
    this.onAuth = null;

    this.init();
  }

  /**
   * Initialize BIP150.
   * @private
   */

  init() {
    if (this.outbound)
      this.peerIdentity = this.db.getKnown(this.hostname);
  }

  /**
   * Test whether the state should be
   * considered authed. This differs
   * for inbound vs. outbound.
   * @returns {Boolean}
   */

  isAuthed() {
    if (this.outbound)
      return this.challengeSent && this.challengeReceived;
    return this.challengeReceived && this.replyReceived;
  }

  /**
   * Handle a received challenge hash.
   * Returns an authreply signature.
   * @param {Buffer} hash
   * @returns {Buffer}
   * @throws on auth failure
   */

  challenge(hash) {
    const type = this.outbound ? 'r' : 'i';

    assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
    assert(!this.challengeReceived, 'Peer challenged twice.');
    this.challengeReceived = true;

    if (hash.equals(consensus.ZERO_HASH))
      throw new Error('Auth failure.');

    const msg = this.hash(this.input.sid, type, this.publicKey);

    if (!ccmp(hash, msg))
      return common.ZERO_SIG;

    if (this.isAuthed()) {
      this.auth = true;
      this.emit('auth');
    }

    // authreply
    return secp256k1.sign(msg, this.privateKey);
  }

  /**
   * Handle a received reply signature.
   * Returns an authpropose hash.
   * @param {Buffer} sig
   * @returns {Buffer}
   * @throws on auth failure
   */

  reply(sig) {
    const type = this.outbound ? 'i' : 'r';

    assert(this.challengeSent, 'Unsolicited reply.');
    assert(!this.replyReceived, 'Peer replied twice.');
    this.replyReceived = true;

    if (sig.equals(common.ZERO_SIG))
      throw new Error('Auth failure.');

    if (!this.peerIdentity)
      return random.randomBytes(32);

    const msg = this.hash(this.output.sid, type, this.peerIdentity);
    const result = secp256k1.verify(msg, sig, this.peerIdentity);

    if (!result)
      return random.randomBytes(32);

    if (this.isAuthed()) {
      this.auth = true;
      this.emit('auth');
      return null;
    }

    assert(this.outbound, 'No challenge received before reply on inbound.');

    // authpropose
    return this.hash(this.input.sid, 'p', this.publicKey);
  }

  /**
   * Handle a received propose hash.
   * Returns an authchallenge hash.
   * @param {Buffer} hash
   * @returns {Buffer}
   */

  propose(hash) {
    assert(!this.outbound, 'Outbound peer tried to propose.');
    assert(!this.challengeSent, 'Unsolicited propose.');
    assert(!this.proposeReceived, 'Peer proposed twice.');
    this.proposeReceived = true;

    const match = this.findAuthorized(hash);

    if (!match)
      return consensus.ZERO_HASH;

    this.peerIdentity = match;

    // Add them in case we ever connect to them.
    this.db.addKnown(this.hostname, this.peerIdentity);

    this.challengeSent = true;

    // authchallenge
    return this.hash(this.output.sid, 'r', this.peerIdentity);
  }

  /**
   * Create initial authchallenge hash
   * for the peer. The peer's identity
   * key must be known.
   * @returns {AuthChallengePacket}
   */

  toChallenge() {
    assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
    assert(this.outbound, 'Cannot challenge an inbound connection.');
    assert(this.peerIdentity, 'Cannot challenge without a peer identity.');

    const msg = this.hash(this.output.sid, 'i', this.peerIdentity);

    assert(!this.challengeSent, 'Cannot initiate challenge twice.');
    this.challengeSent = true;

    return new packets.AuthChallengePacket(msg);
  }

  /**
   * Derive new cipher keys based on
   * BIP150 data. This differs from
   * the regular key derivation of BIP151.
   * @param {Buffer} sid - Sesson ID
   * @param {Buffer} key - `k1` or `k2`
   * @param {Buffer} req - Requesting Identity Key
   * @param {Buffer} res - Response Identity Key
   * @returns {Buffer}
   */

  rekey(sid, key, req, res) {
    const seed = Buffer.allocUnsafe(130);
    sid.copy(seed, 0);
    key.copy(seed, 32);
    req.copy(seed, 64);
    res.copy(seed, 97);
    return hash256.digest(seed);
  }

  /**
   * Rekey the BIP151 input stream
   * using BIP150-style derivation.
   */

  rekeyInput() {
    const stream = this.input;
    const req = this.peerIdentity;
    const res = this.publicKey;
    const k1 = this.rekey(stream.sid, stream.k1, req, res);
    const k2 = this.rekey(stream.sid, stream.k2, req, res);
    stream.rekey(k1, k2);
  }

  /**
   * Rekey the BIP151 output stream
   * using BIP150-style derivation.
   */

  rekeyOutput() {
    const stream = this.output;
    const req = this.publicKey;
    const res = this.peerIdentity;
    const k1 = this.rekey(stream.sid, stream.k1, req, res);
    const k2 = this.rekey(stream.sid, stream.k2, req, res);
    stream.rekey(k1, k2);
  }

  /**
   * Create a hash using the session ID.
   * @param {Buffer} sid
   * @param {String} ch
   * @param {Buffer} key
   * @returns {Buffer}
   */

  hash(sid, ch, key) {
    const data = Buffer.allocUnsafe(66);
    sid.copy(data, 0);
    data[32] = ch.charCodeAt(0);
    key.copy(data, 33);
    return hash256.digest(data);
  }

  /**
   * Find an authorized peer in the Auth
   * DB based on a proposal hash. Note
   * that the hash to find is specific
   * to the state of BIP151. This results
   * in an O(n) search.
   * @param {Buffer} hash
   * @returns {Buffer|null}
   */

  findAuthorized(hash) {
    // Scary O(n) stuff.
    for (const key of this.db.authorized) {
      const msg = this.hash(this.output.sid, 'p', key);

      // XXX Do we really need a constant
      // time compare here? Do it just to
      // be safe I guess.
      if (ccmp(msg, hash))
        return key;
    }

    return null;
  }

  /**
   * Destroy the BIP150 stream and
   * any current running wait job.
   */

  destroy() {
    if (!this.job)
      return;

    this.reject(new Error('BIP150 stream was destroyed.'));
  }

  /**
   * Cleanup wait job.
   * @private
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

    if (this.onAuth) {
      this.removeListener('auth', this.onAuth);
      this.onAuth = null;
    }

    return job;
  }

  /**
   * Resolve the current wait job.
   * @private
   * @param {Object} result
   */

  resolve(result) {
    const job = this.cleanup();
    job.resolve(result);
  }

  /**
   * Reject the current wait job.
   * @private
   * @param {Error} err
   */

  reject(err) {
    const job = this.cleanup();
    job.reject(err);
  }

  /**
   * Wait for handshake to complete.
   * @param {Number} timeout
   * @returns {Promise}
   */

  wait(timeout) {
    return new Promise((resolve, reject) => {
      this._wait(timeout, resolve, reject);
    });
  }

  /**
   * Wait for handshake to complete.
   * @private
   * @param {Number} timeout
   * @param {Function} resolve
   * @param {Function} reject
   */

  _wait(timeout, resolve, reject) {
    assert(!this.auth, 'Cannot wait for init after handshake.');

    this.job = { resolve, reject };

    if (this.outbound && !this.peerIdentity) {
      this.reject(new Error(`No identity for ${this.hostname}.`));
      return;
    }

    this.timeout = setTimeout(() => {
      this.reject(new Error('BIP150 handshake timed out.'));
    }, timeout);

    this.onAuth = this.resolve.bind(this);
    this.once('auth', this.onAuth);
  }

  /**
   * Serialize the peer's identity
   * key as a BIP150 "address".
   * @returns {Base58String}
   */

  getAddress() {
    assert(this.peerIdentity, 'Cannot serialize address.');
    return BIP150.address(this.peerIdentity);
  }

  /**
   * Serialize an identity key as a
   * BIP150 "address".
   * @returns {Base58String}
   */

  static address(key) {
    const bw = bio.write(27);
    bw.writeU8(0x0f);
    bw.writeU16BE(0xff01);
    bw.writeBytes(hash160.digest(key));
    bw.writeChecksum(hash256.digest);
    return base58.encode(bw.render());
  }
}

/**
 * AuthDB
 * @alias module:net.AuthDB
 */

class AuthDB {
  /**
   * Create an auth DB.
   * @constructor
   */

  constructor(options) {
    this.logger = Logger.global;
    this.resolve = dns.lookup;
    this.prefix = null;
    this.dnsKnown = [];

    this.known = new Map();
    this.authorized = [];

    this.init(options);
  }

  /**
   * Initialize authdb with options.
   * @param {Object} options
   */

  init(options) {
    if (!options)
      return;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger.context('authdb');
    }

    if (options.resolve != null) {
      assert(typeof options.resolve === 'function');
      this.resolve = options.resolve;
    }

    if (options.knownPeers != null) {
      assert(typeof options.knownPeers === 'object');
      this.setKnown(options.knownPeers);
    }

    if (options.authPeers != null) {
      assert(Array.isArray(options.authPeers));
      this.setAuthorized(options.authPeers);
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
    }
  }

  /**
   * Open auth database (lookup known peers).
   * @method
   * @returns {Promise}
   */

  async open() {
    await this.readKnown();
    await this.readAuth();
    await this.lookup();
  }

  /**
   * Close auth database.
   * @method
   * @returns {Promise}
   */

  async close() {
    ;
  }

  /**
   * Add a known peer.
   * @param {String} host - Peer Hostname
   * @param {Buffer} key - Identity Key
   */

  addKnown(host, key) {
    assert(typeof host === 'string',
      'Known host must be a string.');

    assert(Buffer.isBuffer(key) && key.length === 33,
      'Invalid public key for known peer.');

    const addr = IP.fromHostname(host);

    if (addr.type === IP.types.DNS) {
      // Defer this for resolution.
      this.dnsKnown.push([addr, key]);
      return;
    }

    this.known.set(host, key);
  }

  /**
   * Add an authorized peer.
   * @param {Buffer} key - Identity Key
   */

  addAuthorized(key) {
    assert(Buffer.isBuffer(key) && key.length === 33,
      'Invalid public key for authorized peer.');
    this.authorized.push(key);
  }

  /**
   * Initialize known peers with a host->key map.
   * @param {Object} map
   */

  setKnown(map) {
    this.known.clear();

    for (const host of Object.keys(map)) {
      const key = map[host];
      this.addKnown(host, key);
    }
  }

  /**
   * Initialize authorized peers with a list of keys.
   * @param {Buffer[]} keys
   */

  setAuthorized(keys) {
    this.authorized.length = 0;

    for (const key of keys)
      this.addAuthorized(key);
  }

  /**
   * Get a known peer key by hostname.
   * @param {String} hostname
   * @returns {Buffer|null}
   */

  getKnown(hostname) {
    const known = this.known.get(hostname);

    if (known)
      return known;

    const addr = IP.fromHostname(hostname);

    return this.known.get(addr.host);
  }

  /**
   * Lookup known peers.
   * @method
   * @returns {Promise}
   */

  async lookup() {
    const jobs = [];

    for (const [addr, key] of this.dnsKnown)
      jobs.push(this.populate(addr, key));

    await Promise.all(jobs);
  }

  /**
   * Populate known peers with hosts.
   * @method
   * @private
   * @param {Object} addr
   * @param {Buffer} key
   * @returns {Promise}
   */

  async populate(addr, key) {
    assert(addr.type === IP.types.DNS, 'Resolved host passed.');

    this.logger.info('Resolving authorized hosts from: %s.', addr.host);

    let hosts;
    try {
      hosts = await this.resolve(addr.host);
    } catch (e) {
      this.logger.error(e);
      return;
    }

    for (let host of hosts) {
      if (addr.port !== 0)
        host = IP.toHostname(host, addr.port);

      this.known.set(host, key);
    }
  }

  /**
   * Parse known peers.
   * @param {String} text
   * @returns {Object}
   */

  async readKnown() {
    if (fs.unsupported)
      return;

    if (!this.prefix)
      return;

    const file = path.join(this.prefix, 'known-peers');

    let text;
    try {
      text = await fs.readFile(file, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    this.parseKnown(text);
  }

  /**
   * Parse known peers.
   * @param {String} text
   * @returns {Object}
   */

  parseKnown(text) {
    assert(typeof text === 'string');

    if (text.charCodeAt(0) === 0xfeff)
      text = text.substring(1);

    text = text.replace(/\r\n/g, '\n');
    text = text.replace(/\r/g, '\n');

    let num = 0;

    for (const chunk of text.split('\n')) {
      const line = chunk.trim();

      num += 1;

      if (line.length === 0)
        continue;

      if (line[0] === '#')
        continue;

      const parts = line.split(/\s+/);

      if (parts.length < 2)
        throw new Error(`No key present on line ${num}: "${line}".`);

      const hosts = parts[0].split(',');

      let host, addr;
      if (hosts.length >= 2) {
        host = hosts[0];
        addr = hosts[1];
      } else {
        host = null;
        addr = hosts[0];
      }

      const key = Buffer.from(parts[1], 'hex');

      if (key.length !== 33)
        throw new Error(`Invalid key on line ${num}: "${parts[1]}".`);

      if (host && host.length > 0)
        this.addKnown(host, key);

      if (addr.length === 0)
        continue;

      this.addKnown(addr, key);
    }
  }

  /**
   * Parse known peers.
   * @param {String} text
   * @returns {Object}
   */

  async readAuth() {
    if (fs.unsupported)
      return;

    if (!this.prefix)
      return;

    const file = path.join(this.prefix, 'authorized-peers');

    let text;
    try {
      text = await fs.readFile(file, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    this.parseAuth(text);
  }

  /**
   * Parse authorized peers.
   * @param {String} text
   * @returns {Buffer[]} keys
   */

  parseAuth(text) {
    assert(typeof text === 'string');

    if (text.charCodeAt(0) === 0xfeff)
      text = text.substring(1);

    text = text.replace(/\r\n/g, '\n');
    text = text.replace(/\r/g, '\n');

    let num = 0;

    for (const chunk of text.split('\n')) {
      const line = chunk.trim();

      num += 1;

      if (line.length === 0)
        continue;

      if (line[0] === '#')
        continue;

      const key = Buffer.from(line, 'hex');

      if (key.length !== 33)
        throw new Error(`Invalid key on line ${num}: "${line}".`);

      this.addAuthorized(key);
    }
  }
}

/*
 * Expose
 */

exports = BIP150;

exports.BIP150 = BIP150;
exports.AuthDB = AuthDB;

module.exports = exports;
