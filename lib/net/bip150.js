/*!
 * bip150.js - peer auth.
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0150.mediawiki
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var packets = require('./packets');
var assert = require('assert');
var constants = require('../protocol/constants');
var ec = require('../crypto/ec');
var BufferWriter = require('../utils/writer');
var base58 = require('../utils/base58');

/**
 * Represents a BIP150 input and output stream.
 * @exports BIP150
 * @constructor
 * @param {BIP151} bip151
 * @property {Boolean} outbound
 * @property {Boolean} challengeReceived
 * @property {Boolean} replyReceived
 * @property {Boolean} proposeReceived
 */

function BIP150(bip151, hostname, outbound, db, identity) {
  if (!(this instanceof BIP150))
    return new BIP150(bip151, hostname, outbound, db, identity);

  assert(bip151, 'BIP150 requires BIP151.');
  assert(typeof hostname === 'string', 'Hostname required.');
  assert(typeof outbound === 'boolean', 'Outbound flag required.');
  assert(db instanceof AuthDB, 'Auth DB required.');
  assert(Buffer.isBuffer(identity), 'Identity key required.');

  EventEmitter.call(this);

  this.bip151 = bip151;
  this.input = bip151.input;
  this.output = bip151.output;

  this.hostname = hostname; // ip & port

  this.db = db;
  this.outbound = outbound;
  this.peerIdentity = null;

  if (this.outbound)
    this.peerIdentity = this.db.getKnown(this.hostname);

  // Identity keypair
  this.privateKey = identity;
  this.publicKey = ec.publicKeyCreate(identity, true);

  this.challengeReceived = false;
  this.replyReceived = false;
  this.proposeReceived = false;
  this.challengeSent = false;
  this.auth = false;
  this.completed = false;
  this.callback = null;
  this.timeout = null;
}

util.inherits(BIP150, EventEmitter);

BIP150.prototype.isAuthed = function isAuthed() {
  if (this.outbound)
    return this.challengeSent && this.challengeReceived;
  return this.challengeReceived && this.replyReceived;
};

BIP150.prototype.challenge = function challenge(hash) {
  var type = this.outbound ? 'r' : 'i';
  var msg, sig;

  assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
  assert(!this.challengeReceived, 'Peer challenged twice.');
  this.challengeReceived = true;

  if (util.equal(hash, constants.ZERO_HASH))
    throw new Error('Auth failure.');

  msg = this.hash(this.input.sid, type, this.publicKey);

  if (!crypto.ccmp(hash, msg))
    return constants.ZERO_SIG64;

  if (this.isAuthed()) {
    this.auth = true;
    this.emit('auth');
  }

  sig = ec.sign(msg, this.privateKey);

  // authreply
  return ec.fromDER(sig);
};

BIP150.prototype.reply = function reply(data) {
  var type = this.outbound ? 'i' : 'r';
  var sig, msg, result;

  assert(this.challengeSent, 'Unsolicited reply.');
  assert(!this.replyReceived, 'Peer replied twice.');
  this.replyReceived = true;

  if (util.equal(data, constants.ZERO_SIG64))
    throw new Error('Auth failure.');

  if (!this.peerIdentity)
    return crypto.randomBytes(32);

  sig = ec.toDER(data);
  msg = this.hash(this.output.sid, type, this.peerIdentity);

  result = ec.verify(msg, sig, this.peerIdentity);

  if (!result)
    return crypto.randomBytes(32);

  if (this.isAuthed()) {
    this.auth = true;
    this.emit('auth');
    return;
  }

  assert(this.outbound, 'No challenge received before reply on inbound.');

  // authpropose
  return this.hash(this.input.sid, 'p', this.publicKey);
};

BIP150.prototype.propose = function propose(hash) {
  var match;

  assert(!this.outbound, 'Outbound peer tried to propose.');
  assert(!this.challengeSent, 'Unsolicited propose.');
  assert(!this.proposeReceived, 'Peer proposed twice.');
  this.proposeReceived = true;

  match = this.findAuthorized(hash);

  if (!match)
    return constants.ZERO_HASH;

  this.peerIdentity = match;

  // Add them in case we ever connect to them.
  this.db.addKnown(this.hostname, this.peerIdentity);

  this.challengeSent = true;

  // authchallenge
  return this.hash(this.output.sid, 'r', this.peerIdentity);
};

BIP150.prototype.toChallenge = function toChallenge() {
  var msg;

  assert(this.bip151.handshake, 'No BIP151 handshake before challenge.');
  assert(this.outbound, 'Cannot challenge an inbound connection.');
  assert(this.peerIdentity, 'Cannot challenge without a peer identity.');

  msg = this.hash(this.output.sid, 'i', this.peerIdentity);

  assert(!this.challengeSent, 'Cannot initiate challenge twice.');
  this.challengeSent = true;

  return new packets.AuthChallengePacket(msg);
};

BIP150.prototype.rekey = function rekey(sid, key, req, res) {
  var seed = new Buffer(130);
  sid.copy(seed, 0);
  key.copy(seed, 32);
  req.copy(seed, 64);
  res.copy(seed, 97);
  return crypto.hash256(seed);
};

BIP150.prototype.rekeyInput = function rekeyInput() {
  var stream = this.input;
  var req = this.peerIdentity;
  var res = this.publicKey;
  var k1 = this.rekey(stream.sid, stream.k1, req, res);
  var k2 = this.rekey(stream.sid, stream.k2, req, res);
  stream.rekey(k1, k2);
};

BIP150.prototype.rekeyOutput = function rekeyOutput() {
  var stream = this.output;
  var req = this.publicKey;
  var res = this.peerIdentity;
  var k1 = this.rekey(stream.sid, stream.k1, req, res);
  var k2 = this.rekey(stream.sid, stream.k2, req, res);
  stream.rekey(k1, k2);
};

BIP150.prototype.hash = function hash(sid, ch, key) {
  var data = new Buffer(66);
  sid.copy(data, 0);
  data[32] = ch.charCodeAt(0);
  key.copy(data, 33);
  return crypto.hash256(data);
};

BIP150.prototype.findAuthorized = function findAuthorized(hash) {
  var i, key, msg;

  // Scary O(n) stuff.
  for (i = 0; i < this.db.authorized.length; i++) {
    key = this.db.authorized[i];
    msg = this.hash(this.output.sid, 'p', key);

    // XXX Do we really need a constant
    // time compare here? Do it just to
    // be safe I guess.
    if (crypto.ccmp(msg, hash))
      return key;
  }
};

BIP150.prototype.destroy = function destroy() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

BIP150.prototype.complete = function complete(err) {
  assert(!this.completed, 'Already completed.');
  assert(this.callback, 'No completion callback.');

  this.completed = true;

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  this.callback(err);
  this.callback = null;
};

BIP150.prototype.wait = function wait(timeout) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self._wait(timeout, co.wrap(resolve, reject));
  });
};

BIP150.prototype._wait = function wait(timeout, callback) {
  var self = this;

  assert(!this.auth, 'Cannot wait for init after handshake.');

  this.callback = callback;

  if (this.outbound && !this.peerIdentity)
    return this.complete(new Error('No identity for ' + this.hostname + '.'));

  this.timeout = setTimeout(function() {
    self.complete(new Error('BIP150 handshake timed out.'));
  }, timeout);

  this.once('auth', function() {
    self.complete();
  });
};

BIP150.prototype.getAddress = function getAddress() {
  assert(this.peerIdentity, 'Cannot serialize address.');
  return BIP150.address(this.peerIdentity);
};

BIP150.address = function address(key) {
  var bw = new BufferWriter();
  bw.writeU8(0x0f);
  bw.writeU16BE(0xff01);
  bw.writeBytes(crypto.hash160(key));
  bw.writeChecksum();
  return base58.encode(bw.render());
};

/**
 * AuthDB
 * @exports AuthDB
 * @constructor
 */

function AuthDB() {
  if (!(this instanceof AuthDB))
    return new AuthDB();

  this.known = {};
  this.authorized = [];
}

AuthDB.prototype.addKnown = function addKnown(host, key) {
  assert(typeof host === 'string');
  assert(Buffer.isBuffer(key) && key.length === 33,
    'Invalid public key for known peer.');
  this.known[host] = key;
};

AuthDB.prototype.addAuthorized = function addAuthorized(key) {
  assert(Buffer.isBuffer(key) && key.length === 33,
    'Invalid public key for authorized peer.');
  this.authorized.push(key);
};

AuthDB.prototype.setKnown = function setKnown(map) {
  var keys = Object.keys(map);
  var i, host, key;

  for (i = 0; i < keys.length; i++) {
    host = keys[i];
    key = map[host];
    this.addKnown(host, key);
  }
};

AuthDB.prototype.setAuthorized = function setAuthorized(keys) {
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    this.addAuthorized(key);
  }
};

AuthDB.prototype.getKnown = function getKnown(host) {
  return this.known[host];
};

/*
 * Expose
 */

exports = BIP150;

exports.BIP150 = BIP150;
exports.AuthDB = AuthDB;

module.exports = exports;
