/*!
 * packets.js - packets for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var constants = require('../protocol/constants');
var utils = require('../utils/utils');
var crypto = require('../crypto/crypto');
var bn = require('bn.js');
var IP = require('../utils/ip');
var assert = utils.assert;

/**
 * Version Packet
 * @constructor
 * @exports VersionPacket
 * @param {Object?} options
 * @param {Number} options.version - Protocol version.
 * @param {Number} options.services - Service bits.
 * @param {Number} options.ts - Timestamp of discovery.
 * @param {NetworkAddress} options.local - Our address.
 * @param {NetworkAddress} options.remote - Their address.
 * @param {BN} options.nonce
 * @param {String} options.agent - User agent string.
 * @param {Number} options.height - Chain height.
 * @param {Boolean} options.relay - Whether transactions
 * should be relayed immediately.
 * @property {Number} version - Protocol version.
 * @property {Number} services - Service bits.
 * @property {Number} ts - Timestamp of discovery.
 * @property {NetworkAddress} local - Our address.
 * @property {NetworkAddress} remote - Their address.
 * @property {BN} nonce
 * @property {String} agent - User agent string.
 * @property {Number} height - Chain height.
 * @property {Boolean} relay - Whether transactions
 * should be relayed immediately.
 */

function VersionPacket(options) {
  if (!(this instanceof VersionPacket))
    return new VersionPacket(options);

  this.version = constants.VERSION;
  this.services = constants.LOCAL_SERVICES;
  this.ts = bcoin.now();
  this.recv = new NetworkAddress();
  this.from = new NetworkAddress();
  this.nonce = new bn(0);
  this.agent = constants.USER_AGENT;
  this.height = 0;
  this.relay = true;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 */

VersionPacket.prototype.fromOptions = function fromOptions(options) {
  if (options.version != null)
    this.version = options.version;

  if (options.services != null)
    this.services = options.services;

  if (options.ts != null)
    this.ts = options.ts;

  if (options.recv)
    this.recv.fromOptions(options.recv);

  if (options.from)
    this.from.fromOptions(options.from);

  if (options.nonce)
    this.nonce = options.nonce;

  if (options.agent)
    this.agent = options.agent;

  if (options.height != null)
    this.height = options.height;

  if (options.relay != null)
    this.relay = options.relay;

  return this;
};

/**
 * Instantiate version packet from options.
 * @param {Object} options
 * @returns {VersionPacket}
 */

VersionPacket.fromOptions = function fromOptions(options) {
  return new VersionPacket().fromOptions(options);
};

/**
 * Serialize version packet.
 * @returns {Buffer}
 */

VersionPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);

  p.write32(this.version);
  p.writeU64(this.services);
  p.write64(this.ts);
  this.recv.toRaw(false, p);
  this.from.toRaw(false, p);
  p.writeU64(this.nonce);
  p.writeVarString(this.agent, 'ascii');
  p.write32(this.height);
  p.writeU8(this.relay ? 1 : 0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Test whether the NETWORK service bit is set.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasNetwork = function hasNetwork() {
  return (this.services & constants.services.NETWORK) !== 0;
};

/**
 * Test whether the BLOOM service bit is set.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasBloom = function hasBloom() {
  return this.version >= 70011
    && (this.services & constants.services.BLOOM) !== 0;
};

/**
 * Test whether the GETUTXO service bit is set.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasUTXO = function hasUTXO() {
  return (this.services & constants.services.GETUTXO) !== 0;
};

/**
 * Test whether the WITNESS service bit is set.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasWitness = function hasWitness() {
  return (this.services & constants.services.WITNESS) !== 0;
};

/**
 * Test whether the protocol version supports getheaders.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasHeaders = function hasHeaders() {
  return this.version >= 31800;
};

/**
 * Test whether the protocol version supports bip152.
 * @returns {Boolean}
 */

VersionPacket.prototype.hasCompact = function hasCompact() {
  return this.version >= 70014;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

VersionPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);

  this.version = p.read32();
  this.services = p.readU53();
  this.ts = p.read53();
  this.recv.fromRaw(p, false);

  if (p.left() > 0) {
    this.from.fromRaw(p, false);
    this.nonce = p.readU64();
  }

  if (p.left() > 0)
    this.agent = p.readVarString('ascii', 256);

  if (p.left() > 0)
    this.height = p.read32();

  if (p.left() > 0)
    this.relay = p.readU8() === 1;

  if (this.version === 10300)
    this.version = 300;

  assert(this.version >= 0, 'Version is negative.');
  assert(this.ts >= 0, 'Timestamp is negative.');
  // assert(this.height >= 0, 'Height is negative.');

  return this;
};

/**
 * Instantiate version packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VersionPacket}
 */

VersionPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new VersionPacket().fromRaw(data, enc);
};

/**
 * Represents a `getblocks` packet.
 * @exports GetBlocksPacket
 * @constructor
 * @param {Hash[]} locator
 * @param {Hash?} stop
 * @property {Hash[]} locator
 * @property {Hash|null} stop
 */

function GetBlocksPacket(locator, stop) {
  if (!(this instanceof GetBlocksPacket))
    return new GetBlocksPacket(locator, stop);

  this.version = constants.VERSION;
  this.locator = locator || [];
  this.stop = stop || null;
}

/**
 * Serialize getblocks packet.
 * @returns {Buffer}
 */

GetBlocksPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var i;

  p.writeU32(this.version);
  p.writeVarint(this.locator.length);

  for (i = 0; i < this.locator.length; i++)
    p.writeHash(this.locator[i]);

  p.writeHash(this.stop || constants.ZERO_HASH);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

GetBlocksPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count;

  this.version = p.readU32();

  count = p.readVarint();

  for (i = 0; i < count; i++)
    this.locator.push(p.readHash('hex'));

  this.stop = p.readHash('hex');

  if (this.stop === constants.NULL_HASH)
    this.stop = null;

  return this;
};

/**
 * Instantiate getblocks packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlocksPacket}
 */

GetBlocksPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new GetBlocksPacket().fromRaw(data);
};

/**
 * Alert Packet
 * @exports AlertPacket
 * @constructor
 * @param {Object} options
 * @property {Number} version
 * @property {Number} relayUntil
 * @property {Number} expiration
 * @property {Number} id
 * @property {Number} cancel
 * @property {Number[]} cancels
 * @property {Number} minVer
 * @property {Number} maxVer
 * @property {String[]} subVers
 * @property {Number} priority
 * @property {String} comment
 * @property {String} statusBar
 * @property {String?} reserved
 * @property {Buffer?} signature - Payload signature.
 */

function AlertPacket(options) {
  var time;

  if (!(this instanceof AlertPacket))
    return new AlertPacket(options);

  time = bcoin.now() + 7 * 86400;

  this.version = 1;
  this.relayUntil = time;
  this.expiration = time;
  this.id = 1;
  this.cancel = 0;
  this.cancels = [];
  this.minVer = 10000;
  this.maxVer = constants.VERSION;
  this.subVers = [];
  this.priority = 100;
  this.comment = '';
  this.statusBar = '';
  this.reserved = '';
  this.signature = null;

  this._payload = null;
  this._hash = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

AlertPacket.prototype.fromOptions = function fromOptions(options) {
  if (options.version != null)
    this.version = options.version;

  if (options.relayUntil != null)
    this.relayUntil = options.relayUntil;

  if (options.expiration != null)
    this.expiration = options.expiration;

  if (options.id != null)
    this.id = options.id;

  if (options.cancel != null)
    this.cancel = options.cancel;

  if (options.cancels)
    this.cancels = options.cancels;

  if (options.minVer != null)
    this.minVer = options.minVer;

  if (options.maxVer != null)
    this.maxVer = options.maxVer;

  if (options.subVers)
    this.subVers = options.subVers;

  if (options.priority != null)
    this.priority = options.priority;

  if (options.comment != null)
    this.comment = options.comment;

  if (options.statusBar != null)
    this.statusBar = options.statusBar;

  if (options.reserved != null)
    this.reserved = options.reserved;

  this.signature = options.signature;

  return this;
};

/**
 * Instantiate alert packet from options.
 * @param {Object} options
 * @returns {AlertPacket}
 */

AlertPacket.fromOptions = function fromOptions(options) {
  return new AlertPacket().fromOptions(options);
};

/**
 * Get the hash256 of the alert payload.
 * @param {String?} enc
 * @returns {Hash}
 */

AlertPacket.prototype.hash = function hash(enc) {
  if (!this._hash)
    this._hash = crypto.hash256(this.toPayload());
  return enc === 'hex' ? this._hash.toString('hex') : this._hash;
};

/**
 * Serialize the packet to its payload.
 * @returns {Buffer}
 */

AlertPacket.prototype.toPayload = function toPayload() {
  if (!this._payload)
    this._payload = this.framePayload();

  return this._payload;
};

/**
 * Sign the alert packet payload.
 * @param {Buffer} key - Private key.
 */

AlertPacket.prototype.sign = function sign(key) {
  this.signature = bcoin.ec.sign(this.hash(), key);
};

/**
 * Verify the alert packet.
 * @param {Buffer} key - Public key.
 * @returns {Boolean}
 */

AlertPacket.prototype.verify = function verify(key) {
  return bcoin.ec.verify(this.hash(), this.signature, key);
};

/**
 * Serialize the alert packet (includes payload _and_ signature).
 * @returns {Buffer}
 */

AlertPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);

  p.writeVarBytes(this.toPayload());
  p.writeVarBytes(this.signature);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize the alert packet payload.
 * @private
 * @returns {Buffer}
 */

AlertPacket.prototype.framePayload = function framePayload(writer) {
  var p = bcoin.writer(writer);
  var i;

  p.write32(this.version);
  p.write64(this.relayUntil);
  p.write64(this.expiration);
  p.write32(this.id);
  p.write32(this.cancel);

  p.writeVarint(this.cancels.length);
  for (i = 0; i < this.cancels.length; i++)
    p.write32(this.cancels[i]);

  p.write32(this.minVer);
  p.write32(this.maxVer);

  p.writeVarint(this.subVers.length);
  for (i = 0; i < this.subVers.length; i++)
    p.writeVarString(this.subVers[i], 'ascii');

  p.write32(this.priority);
  p.writeVarString(this.comment, 'ascii');
  p.writeVarString(this.statusBar, 'ascii');
  p.writeVarString(this.reserved, 'ascii');

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AlertPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count;

  this._payload = p.readVarBytes();
  this.signature = p.readVarBytes();

  p = bcoin.reader(this._payload);

  this.version = p.read32();
  this.relayUntil = p.read53();
  this.expiration = p.read53();
  this.id = p.read32();
  this.cancel = p.read32();

  count = p.readVarint();
  for (i = 0; i < count; i++)
    this.cancels.push(p.read32());

  this.minVer = p.read32();
  this.maxVer = p.read32();

  count = p.readVarint();
  for (i = 0; i < count; i++)
    this.subVers.push(p.readVarString('ascii'));

  this.priority = p.read32();
  this.comment = p.readVarString('ascii');
  this.statusBar = p.readVarString('ascii');
  this.reserved = p.readVarString('ascii');

  return this;
};

/**
 * Instantiate alert packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {AlertPacket}
 */

AlertPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new AlertPacket().fromRaw(data, enc);
};

/**
 * Reject Packet
 * @exports RejectPacket
 * @constructor
 * @property {(Number|String)?} code - Code
 * (see {@link constants.reject}).
 * @property {String?} msg - Message.
 * @property {String?} reason - Reason.
 * @property {(Hash|Buffer)?} data - Transaction or block hash.
 */

function RejectPacket(options) {
  if (!(this instanceof RejectPacket))
    return new RejectPacket(options);

  this.message = '';
  this.code = constants.reject.INVALID;
  this.reason = '';
  this.data = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

RejectPacket.prototype.fromOptions = function fromOptions(options) {
  var code = options.code;

  if (options.message)
    this.message = options.message;

  if (code != null) {
    if (typeof code === 'string')
      code = constants.reject[code.toUpperCase()];

    if (code >= constants.reject.INTERNAL)
      code = constants.reject.INVALID;

    this.code = code;
  }

  if (options.reason)
    this.reason = options.reason;

  if (options.data)
    this.data = options.data;

  return this;
};

/**
 * Instantiate reject packet from options.
 * @param {Object} options
 * @returns {RejectPacket}
 */

RejectPacket.fromOptions = function fromOptions(options) {
  return new RejectPacket().fromOptions(options);
};

/**
 * Serialize reject packet.
 * @returns {Buffer}
 */

RejectPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);

  assert(this.message.length <= 12);
  assert(this.reason.length <= 111);

  p.writeVarString(this.message, 'ascii');
  p.writeU8(this.code);
  p.writeVarString(this.reason, 'ascii');

  if (this.data)
    p.writeHash(this.data);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

RejectPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);

  this.message = p.readVarString('ascii', 12);
  this.code = p.readU8();
  this.reason = p.readVarString('ascii', 111);

  if (this.message === 'block' || this.message === 'tx')
    this.data = p.readHash('hex');
  else
    this.data = null;

  return this;
};

/**
 * Instantiate reject packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {RejectPacket}
 */

RejectPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new RejectPacket().fromRaw(data, enc);
};

/**
 * Inject properties from reason message and object.
 * @private
 * @param {Number} code
 * @param {String} reason
 * @param {(TX|Block)?} obj
 */

RejectPacket.prototype.fromReason = function fromReason(code, reason, obj) {
  if (typeof code === 'string')
    code = constants.reject[code.toUpperCase()];

  if (!code)
    code = constants.reject.INVALID;

  if (code >= constants.reject.INTERNAL)
    code = constants.reject.INVALID;

  this.message = '';
  this.code = code;
  this.reason = reason;

  if (obj) {
    this.message = (obj instanceof bcoin.tx) ? 'tx' : 'block';
    this.data = obj.hash('hex');
  }

  return this;
};

/**
 * Instantiate reject packet from reason message.
 * @param {Number} code
 * @param {String} reason
 * @param {(TX|Block)?} obj
 * @returns {RejectPacket}
 */

RejectPacket.fromReason = function fromReason(code, reason, obj) {
  return new RejectPacket().fromReason(code, reason, obj);
};

/**
 * Instantiate reject packet from verify error.
 * @param {VerifyError} err
 * @param {(TX|Block)?} obj
 * @returns {RejectPacket}
 */

RejectPacket.fromError = function fromError(err, obj) {
  return RejectPacket.fromReason(err.code, err.reason, obj);
};

/**
 * Inspect reject packet.
 * @returns {String}
 */

RejectPacket.prototype.inspect = function inspect() {
  return '<Reject:'
    + ' msg=' + this.message
    + ' code=' + (constants.rejectByVal[this.code] || this.code)
    + ' reason=' + this.reason
    + ' data=' + this.data
    + '>';
};

/**
 * Represents a network address.
 * @exports NetworkAddress
 * @constructor
 * @param {Object} options
 * @param {Number?} options.ts - Timestamp.
 * @param {Number?} options.services - Service bits.
 * @param {String?} options.host - IP address (IPv6 or IPv4).
 * @param {Number?} options.port - Port.
 * @property {Number} id
 * @property {Host} host
 * @property {Number} port
 * @property {Number} services
 * @property {Number} ts
 */

function NetworkAddress(options) {
  if (!(this instanceof NetworkAddress))
    return new NetworkAddress(options);

  this.id = NetworkAddress.uid++;
  this.host = '0.0.0.0';
  this.port = 0;
  this.services = 0;
  this.ts = 0;
  this.hostname = '0.0.0.0:0';

  if (options)
    this.fromOptions(options);
}

/**
 * Globally incremented unique id.
 * @private
 * @type {Number}
 */

NetworkAddress.uid = 0;

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

NetworkAddress.prototype.fromOptions = function fromOptions(options) {
  var host = options.host;

  assert(typeof options.host === 'string');
  assert(typeof options.port === 'number');

  if (IP.version(host) !== -1)
    host = IP.normalize(host);

  this.host = host;
  this.port = options.port;

  if (options.services) {
    assert(typeof options.services === 'number');
    this.services = options.services;
  }

  if (options.ts) {
    assert(typeof options.ts === 'number');
    this.ts = options.ts;
  }

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Instantiate network address from options.
 * @param {Object} options
 * @returns {NetworkAddress}
 */

NetworkAddress.fromOptions = function fromOptions(options) {
  return new NetworkAddress().fromOptions(options);
};

/**
 * Test whether the `host` field is an ip address.
 * @returns {Boolean}
 */

NetworkAddress.prototype.isIP = function isIP() {
  return IP.version(this.host) !== -1;
};

/**
 * Test whether the NETWORK service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasNetwork = function hasNetwork() {
  return (this.services & constants.services.NETWORK) !== 0;
};

/**
 * Test whether the BLOOM service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasBloom = function hasBloom() {
  return (this.services & constants.services.BLOOM) !== 0;
};

/**
 * Test whether the GETUTXO service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasUTXO = function hasUTXO() {
  return (this.services & constants.services.GETUTXO) !== 0;
};

/**
 * Test whether the WITNESS service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasWitness = function hasWitness() {
  return (this.services & constants.services.WITNESS) !== 0;
};

/**
 * Set host.
 * @param {String} host
 */

NetworkAddress.prototype.setHost = function setHost(host) {
  this.host = host;
  this.hostname = IP.hostname(host, this.port);
};

/**
 * Set port.
 * @param {Number} port
 */

NetworkAddress.prototype.setPort = function setPort(port) {
  this.port = port;
  this.hostname = IP.hostname(this.host, port);
};

/**
 * Inspect the network address.
 * @returns {Object}
 */

NetworkAddress.prototype.inspect = function inspect() {
  return '<NetworkAddress:'
    + ' id=' + this.id
    + ' hostname=' + IP.hostname(this.host, this.port)
    + ' services=' + this.services.toString(2)
    + ' date=' + utils.date(this.ts)
    + '>';
};

/**
 * Inject properties from hostname and network.
 * @private
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 */

NetworkAddress.prototype.fromHostname = function fromHostname(hostname, network) {
  var address = IP.parseHost(hostname);

  network = bcoin.network.get(network);

  this.host = address.host;
  this.port = address.port || network.port;
  this.services = constants.services.NETWORK
    | constants.services.BLOOM
    | constants.services.WITNESS;
  this.ts = bcoin.now();

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Instantiate a network address
 * from a hostname (i.e. 127.0.0.1:8333).
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 * @returns {NetworkAddress}
 */

NetworkAddress.fromHostname = function fromHostname(hostname, network) {
  return new NetworkAddress().fromHostname(hostname, network);
};

/**
 * Inject properties from socket.
 * @private
 * @param {net.Socket} socket
 */

NetworkAddress.prototype.fromSocket = function fromSocket(socket) {
  assert(typeof socket.remoteAddress === 'string');
  assert(typeof socket.remotePort === 'number');

  this.host = IP.normalize(socket.remoteAddress);
  this.port = socket.remotePort;
  this.services = constants.services.NETWORK
    | constants.services.BLOOM
    | constants.services.WITNESS;
  this.ts = bcoin.now();

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Instantiate a network address
 * from a socket.
 * @param {net.Socket} socket
 * @returns {NetworkAddress}
 */

NetworkAddress.fromSocket = function fromSocket(hostname) {
  return new NetworkAddress().fromSocket(hostname);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @param {Boolean?} full - Include timestamp.
 */

NetworkAddress.prototype.fromRaw = function fromRaw(data, full) {
  var p = bcoin.reader(data);
  var now = bcoin.now();

  // only version >= 31402
  this.ts = full ? p.readU32() : 0;
  this.services = p.readU53();
  this.host = IP.toString(p.readBytes(16));
  this.port = p.readU16BE();

  if (this.ts <= 100000000 || this.ts > now + 10 * 60)
    this.ts = now - 5 * 24 * 60 * 60;

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Insantiate a network address from serialized data.
 * @param {Buffer} data
 * @param {Boolean?} full - Include timestamp.
 * @returns {NetworkAddress}
 */

NetworkAddress.fromRaw = function fromRaw(data, full) {
  return new NetworkAddress().fromRaw(data, full);
};

/**
 * Serialize network address.
 * @param {Boolean} full - Include timestamp.
 * @returns {Buffer}
 */

NetworkAddress.prototype.toRaw = function toRaw(full, writer) {
  var p = bcoin.writer(writer);

  if (full)
    p.writeU32(this.ts);

  p.writeU64(this.services);
  p.writeBytes(IP.toBuffer(this.host));
  p.writeU16BE(this.port);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Represents a `getutxos` packet.
 * @exports GetUTXOsPacket
 * @constructor
 * @param {Boolean} mempool
 * @param {Outpoint[]} prevout
 * @property {Boolean} mempool
 * @property {Outpoint[]} prevout
 */

function GetUTXOsPacket(mempool, prevout) {
  if (!(this instanceof GetUTXOsPacket))
    return new GetUTXOsPacket(mempool, prevout);

  this.mempool = mempool || false;
  this.prevout = prevout || [];
}

/**
 * Serialize getutxos packet.
 * @returns {Buffer}
 */

GetUTXOsPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var i;

  p.writeU8(this.mempool ? 1 : 0);
  p.writeVarint(this.prevout.length);

  for (i = 0; i < this.prevout.length; i++)
    this.prevout[i].toRaw(p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

GetUTXOsPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count;

  this.mempool = p.readU8() === 1;

  count = p.readVarint();

  for (i = 0; i < count; i++)
    this.prevout.push(bcoin.outpoint.fromRaw(p));

  return this;
};

/**
 * Instantiate getutxos packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlocksPacket}
 */

GetUTXOsPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new GetUTXOsPacket().fromRaw(data);
};

/**
 * Represents a `utxos` packet.
 * @exports UTXOsPacket
 * @constructor
 * @param {Object} options
 * @property {Number} height
 * @property {Hash} tip
 * @property {Boolean[]} hits
 * @property {Coin[]} coins
 */

function UTXOsPacket(options) {
  if (!(this instanceof UTXOsPacket))
    return new UTXOsPacket(options);

  this.height = -1;
  this.tip = constants.NULL_HASH;
  this.hits = [];
  this.coins = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Buffer} data
 */

UTXOsPacket.prototype.fromOptions = function fromOptions(options) {
  if (options.height != null) {
    assert(utils.isNumber(options.height));
    this.height = options.height;
  }

  if (options.tip) {
    assert(typeof options.tip === 'string');
    this.tip = options.tip;
  }

  if (options.hits) {
    assert(Array.isArray(options.hits));
    this.hits = options.hits;
  }

  if (options.coins) {
    assert(Array.isArray(options.coins));
    this.coins = options.coins;
  }

  return this;
};

/**
 * Instantiate utxos packet from options.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlocksPacket}
 */

UTXOsPacket.fromOptions = function fromOptions(options) {
  return new UTXOsPacket().fromOptions(options);
};

/**
 * Serialize utxos packet.
 * @returns {Buffer}
 */

UTXOsPacket.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var map = new Buffer((this.hits.length + 7) / 8 | 0);
  var i, bit, oct, coin, height;

  for (i = 0; i < this.hits.length; i++) {
    bit = i % 8;
    oct = (i - bit) / 8;
    map[oct] |= +this.hits[i] << (7 - bit);
  }

  p.writeU32(this.height);
  p.writeHash(this.tip);
  p.writeVarBytes(map);
  p.writeVarInt(this.coins.length);

  for (i = 0; i < this.coins.length; i++) {
    coin = this.coins[i];
    height = coin.height;

    if (height === -1)
      height = 0x7fffffff;

    p.writeU32(coin.version);
    p.writeU32(height);
    p.write64(coin.value);
    p.writeVarBytes(coin.script.toRaw());
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

UTXOsPacket.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, bit, oct, coin, output;
  var version, height, map, count;

  this.height = p.readU32();
  this.tip = p.readHash('hex');

  map = p.readVarBytes();
  count = p.readVarint();

  for (i = 0; i < map.length * 8; i++) {
    bit = i % 8;
    oct = (i - bit) / 8;
    this.hits.push((map[oct] >> (7 - bit)) & 1);
  }

  for (i = 0; i < count; i++) {
    version = p.readU32();
    height = p.readU32();
    coin = new bcoin.coin();

    if (height === 0x7fffffff)
      height = -1;

    output = bcoin.output.fromRaw(p);

    coin.version = version;
    coin.height = height;
    coin.script = output.script;
    coin.value = output.value;

    this.coins.push(coin);
  }

  return this;
};

/**
 * Instantiate utxos packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlocksPacket}
 */

UTXOsPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new UTXOsPacket().fromRaw(data);
};

/*
 * Expose
 */

exports.VersionPacket = VersionPacket;
exports.GetBlocksPacket = GetBlocksPacket;
exports.AlertPacket = AlertPacket;
exports.RejectPacket = RejectPacket;
exports.GetUTXOsPacket = GetUTXOsPacket;
exports.UTXOsPacket = UTXOsPacket;
exports.NetworkAddress = NetworkAddress;
