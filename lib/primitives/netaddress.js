/*!
 * netaddress.js - network address object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const common = require('../net/common');
const Network = require('../protocol/network');
const util = require('../utils/util');
const IP = require('../utils/ip');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');

/**
 * Represents a network address.
 * @alias module:primitives.NetAddress
 * @constructor
 * @param {Object} options
 * @param {Number?} options.ts - Timestamp.
 * @param {Number?} options.services - Service bits.
 * @param {String?} options.host - IP address (IPv6 or IPv4).
 * @param {Number?} options.port - Port.
 * @property {Host} host
 * @property {Number} port
 * @property {Number} services
 * @property {Number} ts
 */

function NetAddress(options) {
  if (!(this instanceof NetAddress))
    return new NetAddress(options);

  this.host = '0.0.0.0';
  this.port = 0;
  this.services = 0;
  this.ts = 0;
  this.hostname = '0.0.0.0:0';
  this.raw = IP.ZERO_IP;

  if (options)
    this.fromOptions(options);
}

/**
 * Default services for
 * unknown outbound peers.
 * @const {Number}
 * @default
 */

NetAddress.DEFAULT_SERVICES = 0
  | common.services.NETWORK
  | common.services.WITNESS
  | common.services.BLOOM;

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

NetAddress.prototype.fromOptions = function fromOptions(options) {
  assert(typeof options.host === 'string');
  assert(typeof options.port === 'number');

  this.raw = IP.toBuffer(options.host);
  this.host = IP.toString(this.raw);
  this.port = options.port;

  if (options.services) {
    assert(typeof options.services === 'number');
    this.services = options.services;
  }

  if (options.ts) {
    assert(typeof options.ts === 'number');
    this.ts = options.ts;
  }

  this.hostname = IP.toHostname(this.host, this.port);

  return this;
};

/**
 * Instantiate network address from options.
 * @param {Object} options
 * @returns {NetAddress}
 */

NetAddress.fromOptions = function fromOptions(options) {
  return new NetAddress().fromOptions(options);
};

/**
 * Test whether required services are available.
 * @param {Number} services
 * @returns {Boolean}
 */

NetAddress.prototype.hasServices = function hasServices(services) {
  return (this.services & services) === services;
};

/**
 * Test whether the address is IPv4.
 * @returns {Boolean}
 */

NetAddress.isIPv4 = function isIPv4() {
  return IP.isIPv4(this.raw);
};

/**
 * Test whether the address is IPv6.
 * @returns {Boolean}
 */

NetAddress.isIPv6 = function isIPv6() {
  return IP.isIPv6(this.raw);
};

/**
 * Test whether the host is null.
 * @returns {Boolean}
 */

NetAddress.prototype.isNull = function isNull() {
  return IP.isNull(this.raw);
};

/**
 * Test whether the host is a local address.
 * @returns {Boolean}
 */

NetAddress.prototype.isLocal = function isLocal() {
  return IP.isLocal(this.raw);
};

/**
 * Test whether the host is valid.
 * @returns {Boolean}
 */

NetAddress.prototype.isValid = function isValid() {
  return IP.isValid(this.raw);
};

/**
 * Test whether the host is routable.
 * @returns {Boolean}
 */

NetAddress.prototype.isRoutable = function isRoutable() {
  return IP.isRoutable(this.raw);
};

/**
 * Test whether the host is an onion address.
 * @returns {Boolean}
 */

NetAddress.prototype.isOnion = function isOnion() {
  return IP.isOnion(this.raw);
};

/**
 * Compare against another network address.
 * @returns {Boolean}
 */

NetAddress.prototype.equal = function equal(addr) {
  return this.compare(addr) === 0;
};

/**
 * Compare against another network address.
 * @returns {Number}
 */

NetAddress.prototype.compare = function compare(addr) {
  let cmp = this.raw.compare(addr.raw);

  if (cmp !== 0)
    return cmp;

  return this.port - addr.port;
};

/**
 * Get reachable score to destination.
 * @param {NetAddress} dest
 * @returns {Number}
 */

NetAddress.prototype.getReachability = function getReachability(dest) {
  return IP.getReachability(this.raw, dest.raw);
};

/**
 * Set null host.
 */

NetAddress.prototype.setNull = function setNull() {
  this.raw = IP.ZERO_IP;
  this.host = '0.0.0.0';
  this.hostname = IP.toHostname(this.host, this.port);
};

/**
 * Set host.
 * @param {String} host
 */

NetAddress.prototype.setHost = function setHost(host) {
  this.raw = IP.toBuffer(host);
  this.host = IP.toString(this.raw);
  this.hostname = IP.toHostname(this.host, this.port);
};

/**
 * Set port.
 * @param {Number} port
 */

NetAddress.prototype.setPort = function setPort(port) {
  assert(port >= 0 && port <= 0xffff);
  this.port = port;
  this.hostname = IP.toHostname(this.host, port);
};

/**
 * Inject properties from host, port, and network.
 * @private
 * @param {String} host
 * @param {Number} port
 * @param {(Network|NetworkType)?} network
 */

NetAddress.prototype.fromHost = function fromHost(host, port, network) {
  network = Network.get(network);

  assert(port >= 0 && port <= 0xffff);

  this.raw = IP.toBuffer(host);
  this.host = IP.toString(this.raw);
  this.port = port;
  this.services = NetAddress.DEFAULT_SERVICES;
  this.ts = network.now();

  this.hostname = IP.toHostname(this.host, this.port);

  return this;
};

/**
 * Instantiate a network address
 * from a host and port.
 * @param {String} host
 * @param {Number} port
 * @param {(Network|NetworkType)?} network
 * @returns {NetAddress}
 */

NetAddress.fromHost = function fromHost(host, port, network) {
  return new NetAddress().fromHost(host, port, network);
};

/**
 * Inject properties from hostname and network.
 * @private
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 */

NetAddress.prototype.fromHostname = function fromHostname(hostname, network) {
  let addr;

  network = Network.get(network);

  addr = IP.fromHostname(hostname, network.port);

  return this.fromHost(addr.host, addr.port, network);
};

/**
 * Instantiate a network address
 * from a hostname (i.e. 127.0.0.1:8333).
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 * @returns {NetAddress}
 */

NetAddress.fromHostname = function fromHostname(hostname, network) {
  return new NetAddress().fromHostname(hostname, network);
};

/**
 * Inject properties from socket.
 * @private
 * @param {net.Socket} socket
 */

NetAddress.prototype.fromSocket = function fromSocket(socket, network) {
  let host = socket.remoteAddress;
  let port = socket.remotePort;
  assert(typeof host === 'string');
  assert(typeof port === 'number');
  return this.fromHost(IP.normalize(host), port, network);
};

/**
 * Instantiate a network address
 * from a socket.
 * @param {net.Socket} socket
 * @returns {NetAddress}
 */

NetAddress.fromSocket = function fromSocket(hostname, network) {
  return new NetAddress().fromSocket(hostname, network);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @param {Boolean?} full - Include timestamp.
 */

NetAddress.prototype.fromReader = function fromReader(br, full) {
  this.ts = full ? br.readU32() : 0;
  this.services = br.readU32();

  // Note: hi service bits
  // are currently unused.
  br.readU32();

  this.raw = br.readBytes(16);
  this.host = IP.toString(this.raw);
  this.port = br.readU16BE();
  this.hostname = IP.toHostname(this.host, this.port);

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @param {Boolean?} full - Include timestamp.
 */

NetAddress.prototype.fromRaw = function fromRaw(data, full) {
  return this.fromReader(new BufferReader(data), full);
};

/**
 * Insantiate a network address from buffer reader.
 * @param {BufferReader} br
 * @param {Boolean?} full - Include timestamp.
 * @returns {NetAddress}
 */

NetAddress.fromReader = function fromReader(br, full) {
  return new NetAddress().fromReader(br, full);
};

/**
 * Insantiate a network address from serialized data.
 * @param {Buffer} data
 * @param {Boolean?} full - Include timestamp.
 * @returns {NetAddress}
 */

NetAddress.fromRaw = function fromRaw(data, full) {
  return new NetAddress().fromRaw(data, full);
};

/**
 * Write network address to a buffer writer.
 * @param {BufferWriter} bw
 * @param {Boolean?} full - Include timestamp.
 * @returns {Buffer}
 */

NetAddress.prototype.toWriter = function toWriter(bw, full) {
  if (full)
    bw.writeU32(this.ts);

  bw.writeU32(this.services);
  bw.writeU32(0);
  bw.writeBytes(this.raw);
  bw.writeU16BE(this.port);

  return bw;
};

/**
 * Calculate serialization size of address.
 * @returns {Number}
 */

NetAddress.prototype.getSize = function getSize(full) {
  return 26 + (full ? 4 : 0);
};

/**
 * Serialize network address.
 * @param {Boolean?} full - Include timestamp.
 * @returns {Buffer}
 */

NetAddress.prototype.toRaw = function toRaw(full) {
  let size = this.getSize(full);
  return this.toWriter(new StaticWriter(size), full).render();
};

/**
 * Convert net address to json-friendly object.
 * @returns {Object}
 */

NetAddress.prototype.toJSON = function toJSON() {
  return {
    host: this.host,
    port: this.port,
    services: this.services,
    ts: this.ts
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @returns {NetAddress}
 */

NetAddress.prototype.fromJSON = function fromJSON(json) {
  assert(util.isNumber(json.port));
  assert(json.port >= 0 && json.port <= 0xffff);
  assert(util.isNumber(json.services));
  assert(util.isNumber(json.ts));
  this.raw = IP.toBuffer(json.host);
  this.host = json.host;
  this.port = json.port;
  this.services = json.services;
  this.ts = json.ts;
  this.hostname = IP.toHostname(this.host, this.port);
  return this;
};

/**
 * Instantiate net address from json object.
 * @param {Object} json
 * @returns {NetAddress}
 */

NetAddress.fromJSON = function fromJSON(json) {
  return new NetAddress().fromJSON(json);
};

/**
 * Inspect the network address.
 * @returns {Object}
 */

NetAddress.prototype.inspect = function inspect() {
  return '<NetAddress:'
    + ` hostname=${this.hostname}`
    + ` services=${this.services.toString(2)}`
    + ` date=${util.date(this.ts)}`
    + '>';
};

/*
 * Expose
 */

module.exports = NetAddress;
