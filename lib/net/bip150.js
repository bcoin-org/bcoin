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
const util = require('../utils/util');
const co = require('../utils/co');
const digest = require('../crypto/digest');
const random = require('../crypto/random');
const ccmp = require('../crypto/ccmp');
const packets = require('./packets');
const secp256k1 = require('../crypto/secp256k1');
const StaticWriter = require('../utils/staticwriter');
const base58 = require('../utils/base58');
const encoding = require('../utils/encoding');
const IP = require('../utils/ip');
const dns = require('./dns');
const fs = require('../utils/fs');
const Logger = require('../node/logger');

/**
 * Represents a BIP150 input/output stream.
 * @alias module:net.BIP150
 * @constructor
 * @param {BIP151} bip151
 * @param {String} host
 * @param {Boolean} outbound
 * @param {AuthDB} db
 * @param {Buffer} key - Identity key.
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

function BIP150(bip151, host, outbound, db, key) {
  if (!(this instanceof BIP150))
    return new BIP150(bip151, host, outbound, db, key);

  EventEmitter.call(this);

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

  this._init();
}

util.inherits(BIP150, EventEmitter);

/**
 * Initialize BIP150.
 * @private
 */

BIP150.prototype._init = function _init() {
  if (this.outbound)
    this.peerIdentity = this.db.getKnown(this.hostname);
};

/**
 * Test whether the state should be
 * considered authed. This differs
 * for inbound vs. outbound.
 * @returns {Boolean}
 */

BIP150.prototype.isAuthed = function isAuthed() {
  if (this.outbound)
    return this.challengeSent && this.challengeReceived;
  return this.challengeReceived && this.replyReceived;
};

/**
 * Handle a received challenge hash.
 * Returns an authreply signature.
 * @param {Buffer} hash
 * @returns {Buffer}
 * @throws on auth failure
 */

BIP150.prototype.challenge = function challenge(hash) {
  let type = this.outbound ? 'r' : 'i';
  let msg, sig;

  assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
  assert(!this.challengeReceived, 'Peer challenged twice.');
  this.challengeReceived = true;

  if (hash.equals(encoding.ZERO_HASH))
    throw new Error('Auth failure.');

  msg = this.hash(this.input.sid, type, this.publicKey);

  if (!ccmp(hash, msg))
    return encoding.ZERO_SIG64;

  if (this.isAuthed()) {
    this.auth = true;
    this.emit('auth');
  }

  sig = secp256k1.sign(msg, this.privateKey);

  // authreply
  return secp256k1.fromDER(sig);
};

/**
 * Handle a received reply signature.
 * Returns an authpropose hash.
 * @param {Buffer} data
 * @returns {Buffer}
 * @throws on auth failure
 */

BIP150.prototype.reply = function reply(data) {
  let type = this.outbound ? 'i' : 'r';
  let sig, msg, result;

  assert(this.challengeSent, 'Unsolicited reply.');
  assert(!this.replyReceived, 'Peer replied twice.');
  this.replyReceived = true;

  if (data.equals(encoding.ZERO_SIG64))
    throw new Error('Auth failure.');

  if (!this.peerIdentity)
    return random.randomBytes(32);

  sig = secp256k1.toDER(data);
  msg = this.hash(this.output.sid, type, this.peerIdentity);

  result = secp256k1.verify(msg, sig, this.peerIdentity);

  if (!result)
    return random.randomBytes(32);

  if (this.isAuthed()) {
    this.auth = true;
    this.emit('auth');
    return;
  }

  assert(this.outbound, 'No challenge received before reply on inbound.');

  // authpropose
  return this.hash(this.input.sid, 'p', this.publicKey);
};

/**
 * Handle a received propose hash.
 * Returns an authchallenge hash.
 * @param {Buffer} hash
 * @returns {Buffer}
 */

BIP150.prototype.propose = function propose(hash) {
  let match;

  assert(!this.outbound, 'Outbound peer tried to propose.');
  assert(!this.challengeSent, 'Unsolicited propose.');
  assert(!this.proposeReceived, 'Peer proposed twice.');
  this.proposeReceived = true;

  match = this.findAuthorized(hash);

  if (!match)
    return encoding.ZERO_HASH;

  this.peerIdentity = match;

  // Add them in case we ever connect to them.
  this.db.addKnown(this.hostname, this.peerIdentity);

  this.challengeSent = true;

  // authchallenge
  return this.hash(this.output.sid, 'r', this.peerIdentity);
};

/**
 * Create initial authchallenge hash
 * for the peer. The peer's identity
 * key must be known.
 * @returns {AuthChallengePacket}
 */

BIP150.prototype.toChallenge = function toChallenge() {
  let msg;

  assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
  assert(this.outbound, 'Cannot challenge an inbound connection.');
  assert(this.peerIdentity, 'Cannot challenge without a peer identity.');

  msg = this.hash(this.output.sid, 'i', this.peerIdentity);

  assert(!this.challengeSent, 'Cannot initiate challenge twice.');
  this.challengeSent = true;

  return new packets.AuthChallengePacket(msg);
};

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

BIP150.prototype.rekey = function rekey(sid, key, req, res) {
  let seed = Buffer.allocUnsafe(130);
  sid.copy(seed, 0);
  key.copy(seed, 32);
  req.copy(seed, 64);
  res.copy(seed, 97);
  return digest.hash256(seed);
};

/**
 * Rekey the BIP151 input stream
 * using BIP150-style derivation.
 */

BIP150.prototype.rekeyInput = function rekeyInput() {
  let stream = this.input;
  let req = this.peerIdentity;
  let res = this.publicKey;
  let k1 = this.rekey(stream.sid, stream.k1, req, res);
  let k2 = this.rekey(stream.sid, stream.k2, req, res);
  stream.rekey(k1, k2);
};

/**
 * Rekey the BIP151 output stream
 * using BIP150-style derivation.
 */

BIP150.prototype.rekeyOutput = function rekeyOutput() {
  let stream = this.output;
  let req = this.publicKey;
  let res = this.peerIdentity;
  let k1 = this.rekey(stream.sid, stream.k1, req, res);
  let k2 = this.rekey(stream.sid, stream.k2, req, res);
  stream.rekey(k1, k2);
};

/**
 * Create a hash using the session ID.
 * @param {Buffer} sid
 * @param {String} ch
 * @param {Buffer} key
 * @returns {Buffer}
 */

BIP150.prototype.hash = function hash(sid, ch, key) {
  let data = Buffer.allocUnsafe(66);
  sid.copy(data, 0);
  data[32] = ch.charCodeAt(0);
  key.copy(data, 33);
  return digest.hash256(data);
};

/**
 * Find an authorized peer in the Auth
 * DB based on a proposal hash. Note
 * that the hash to find is specific
 * to the state of BIP151. This results
 * in an O(n) search.
 * @param {Buffer} hash
 * @returns {Buffer|null}
 */

BIP150.prototype.findAuthorized = function findAuthorized(hash) {
  // Scary O(n) stuff.
  for (let key of this.db.authorized) {
    let msg = this.hash(this.output.sid, 'p', key);

    // XXX Do we really need a constant
    // time compare here? Do it just to
    // be safe I guess.
    if (ccmp(msg, hash))
      return key;
  }
};

/**
 * Destroy the BIP150 stream and
 * any current running wait job.
 */

BIP150.prototype.destroy = function destroy() {
  if (!this.job)
    return;

  this.reject(new Error('BIP150 stream was destroyed.'));
};

/**
 * Cleanup wait job.
 * @private
 * @returns {Job}
 */

BIP150.prototype.cleanup = function cleanup(err) {
  let job = this.job;

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
};

/**
 * Resolve the current wait job.
 * @private
 * @param {Object} result
 */

BIP150.prototype.resolve = function resolve(result) {
  let job = this.cleanup();
  job.resolve(result);
};

/**
 * Reject the current wait job.
 * @private
 * @param {Error} err
 */

BIP150.prototype.reject = function reject(err) {
  let job = this.cleanup();
  job.reject(err);
};

/**
 * Wait for handshake to complete.
 * @param {Number} timeout
 * @returns {Promise}
 */

BIP150.prototype.wait = function wait(timeout) {
  return new Promise((resolve, reject) => {
    this._wait(timeout, resolve, reject);
  });
};

/**
 * Wait for handshake to complete.
 * @private
 * @param {Number} timeout
 * @param {Function} resolve
 * @param {Function} reject
 */

BIP150.prototype._wait = function wait(timeout, resolve, reject) {
  assert(!this.auth, 'Cannot wait for init after handshake.');

  this.job = co.job(resolve, reject);

  if (this.outbound && !this.peerIdentity) {
    this.reject(new Error(`No identity for ${this.hostname}.`));
    return;
  }

  this.timeout = setTimeout(() => {
    this.reject(new Error('BIP150 handshake timed out.'));
  }, timeout);

  this.onAuth = this.resolve.bind(this);
  this.once('auth', this.onAuth);
};

/**
 * Serialize the peer's identity
 * key as a BIP150 "address".
 * @returns {Base58String}
 */

BIP150.prototype.getAddress = function getAddress() {
  assert(this.peerIdentity, 'Cannot serialize address.');
  return BIP150.address(this.peerIdentity);
};

/**
 * Serialize an identity key as a
 * BIP150 "address".
 * @returns {Base58String}
 */

BIP150.address = function address(key) {
  let bw = new StaticWriter(27);
  bw.writeU8(0x0f);
  bw.writeU16BE(0xff01);
  bw.writeBytes(digest.hash160(key));
  bw.writeChecksum();
  return base58.encode(bw.render());
};

/**
 * AuthDB
 * @alias module:net.AuthDB
 * @constructor
 */

function AuthDB(options) {
  if (!(this instanceof AuthDB))
    return new AuthDB(options);

  this.logger = Logger.global;
  this.resolve = dns.lookup;
  this.prefix = null;
  this.dnsKnown = [];

  this.known = {};
  this.authorized = [];

  this._init(options);
}

/**
 * Initialize authdb with options.
 * @param {Object} options
 */

AuthDB.prototype._init = function _init(options) {
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
};

/**
 * Open auth database (lookup known peers).
 * @method
 * @returns {Promise}
 */

AuthDB.prototype.open = async function open() {
  await this.readKnown();
  await this.readAuth();
  await this.lookup();
};

/**
 * Close auth database.
 * @method
 * @returns {Promise}
 */

AuthDB.prototype.close = async function close() {
  ;
};

/**
 * Add a known peer.
 * @param {String} host - Peer Hostname
 * @param {Buffer} key - Identity Key
 */

AuthDB.prototype.addKnown = function addKnown(host, key) {
  let addr;

  assert(typeof host === 'string',
    'Known host must be a string.');

  assert(Buffer.isBuffer(key) && key.length === 33,
    'Invalid public key for known peer.');

  addr = IP.fromHostname(host);

  if (addr.type === IP.types.DNS) {
    // Defer this for resolution.
    this.dnsKnown.push([addr, key]);
    return;
  }

  this.known[host] = key;
};

/**
 * Add an authorized peer.
 * @param {Buffer} key - Identity Key
 */

AuthDB.prototype.addAuthorized = function addAuthorized(key) {
  assert(Buffer.isBuffer(key) && key.length === 33,
    'Invalid public key for authorized peer.');
  this.authorized.push(key);
};

/**
 * Initialize known peers with a host->key map.
 * @param {Object} map
 */

AuthDB.prototype.setKnown = function setKnown(map) {
  let keys = Object.keys(map);

  this.known = {};

  for (let host of keys) {
    let key = map[host];
    this.addKnown(host, key);
  }
};

/**
 * Initialize authorized peers with a list of keys.
 * @param {Buffer[]} keys
 */

AuthDB.prototype.setAuthorized = function setAuthorized(keys) {
  this.authorized.length = 0;

  for (let key of keys)
    this.addAuthorized(key);
};

/**
 * Get a known peer key by hostname.
 * @param {String} hostname
 * @returns {Buffer|null}
 */

AuthDB.prototype.getKnown = function getKnown(hostname) {
  let known = this.known[hostname];
  let addr;

  if (known)
    return known;

  addr = IP.fromHostname(hostname);

  return this.known[addr.host];
};

/**
 * Lookup known peers.
 * @method
 * @returns {Promise}
 */

AuthDB.prototype.lookup = async function lookup() {
  let jobs = [];

  for (let addr of this.dnsKnown)
    jobs.push(this.populate(addr[0], addr[1]));

  await Promise.all(jobs);
};

/**
 * Populate known peers with hosts.
 * @method
 * @private
 * @param {Object} addr
 * @param {Buffer} key
 * @returns {Promise}
 */

AuthDB.prototype.populate = async function populate(addr, key) {
  let hosts;

  assert(addr.type === IP.types.DNS, 'Resolved host passed.');

  this.logger.info('Resolving authorized hosts from: %s.', addr.host);

  try {
    hosts = await this.resolve(addr.host);
  } catch (e) {
    this.logger.error(e);
    return;
  }

  for (let host of hosts) {
    if (addr.port !== 0)
      host = IP.toHostname(host, addr.port);

    this.known[host] = key;
  }
};

/**
 * Parse known peers.
 * @param {String} text
 * @returns {Object}
 */

AuthDB.prototype.readKnown = async function readKnown() {
  let file, text;

  if (fs.unsupported)
    return;

  if (!this.prefix)
    return;

  file = path.join(this.prefix, 'known-peers');

  try {
    text = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT')
      return;
    throw e;
  }

  this.parseKnown(text);
};

/**
 * Parse known peers.
 * @param {String} text
 * @returns {Object}
 */

AuthDB.prototype.parseKnown = function parseKnown(text) {
  let lines = text.split(/\n+/);

  for (let line of lines) {
    let parts, hostname, host, ip, key;

    line = line.trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    parts = line.split(/\s+/);

    if (parts.length < 2)
      continue;

    hostname = parts[0].trim().split(',');

    if (hostname.length >= 2) {
      host = hostname[0];
      ip = hostname[1];
    } else {
      host = null;
      ip = hostname[0];
    }

    key = parts[1].trim();
    key = Buffer.from(key, 'hex');

    if (key.length !== 33)
      throw new Error(`Invalid key: ${parts[1]}.`);

    if (host && host.length > 0)
      this.addKnown(host, key);

    if (ip.length === 0)
      continue;

    this.addKnown(ip, key);
  }
};

/**
 * Parse known peers.
 * @param {String} text
 * @returns {Object}
 */

AuthDB.prototype.readAuth = async function readAuth() {
  let file, text;

  if (fs.unsupported)
    return;

  if (!this.prefix)
    return;

  file = path.join(this.prefix, 'authorized-peers');

  try {
    text = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT')
      return;
    throw e;
  }

  this.parseAuth(text);
};

/**
 * Parse authorized peers.
 * @param {String} text
 * @returns {Buffer[]} keys
 */

AuthDB.prototype.parseAuth = function parseAuth(text) {
  let lines = text.split(/\n+/);

  for (let line of lines) {
    let key;

    line = line.trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    key = Buffer.from(line, 'hex');

    if (key.length !== 33)
      throw new Error(`Invalid key: ${line}.`);

    this.addAuthorized(key);
  }
};

/*
 * Expose
 */

exports = BIP150;

exports.BIP150 = BIP150;
exports.AuthDB = AuthDB;

module.exports = exports;
