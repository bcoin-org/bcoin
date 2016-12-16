/*!
 * netaddress.js - network address object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var util = require('../utils/util');
var IP = require('../utils/ip');
var assert = require('assert');
var StaticWriter = require('../utils/staticwriter');
var BufferReader = require('../utils/reader');

/**
 * Represents a network address.
 * @exports NetworkAddress
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

function NetworkAddress(options) {
  if (!(this instanceof NetworkAddress))
    return new NetworkAddress(options);

  this.host = '0.0.0.0';
  this.port = 0;
  this.services = 0;
  this.ts = 0;
  this.hostname = '0.0.0.0:0';

  this.prev = null;
  this.next = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

NetworkAddress.prototype.fromOptions = function fromOptions(options) {
  assert(typeof options.host === 'string');
  assert(typeof options.port === 'number');

  assert(IP.version(options.host) !== -1);

  this.host = IP.normalize(options.host);
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
 * Inject properties from host, port, and network.
 * @private
 * @param {String} host
 * @param {Number} port
 * @param {(Network|NetworkType)?} network
 */

NetworkAddress.prototype.fromHost = function fromHost(host, port, network) {
  network = Network.get(network);

  assert(IP.version(host) !== -1);

  this.host = host;
  this.port = port || network.port;
  this.services = constants.services.NETWORK
    | constants.services.BLOOM
    | constants.services.WITNESS;
  this.ts = network.now();

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Instantiate a network address
 * from a host and port.
 * @param {String} host
 * @param {Number} port
 * @param {(Network|NetworkType)?} network
 * @returns {NetworkAddress}
 */

NetworkAddress.fromHost = function fromHost(host, port, network) {
  return new NetworkAddress().fromHost(host, port, network);
};

/**
 * Inject properties from hostname and network.
 * @private
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 */

NetworkAddress.prototype.fromHostname = function fromHostname(hostname, network) {
  var addr;
  network = Network.get(network);
  addr = IP.parseHost(hostname, network.port);
  return this.fromHost(addr.host, addr.port, network);
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

NetworkAddress.prototype.fromSocket = function fromSocket(socket, network) {
  var host = socket.remoteAddress;
  var port = socket.remotePort;
  assert(typeof host === 'string');
  assert(typeof port === 'number');
  return this.fromHost(IP.normalize(host), port, network);
};

/**
 * Instantiate a network address
 * from a socket.
 * @param {net.Socket} socket
 * @returns {NetworkAddress}
 */

NetworkAddress.fromSocket = function fromSocket(hostname, network) {
  return new NetworkAddress().fromSocket(hostname, network);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @param {Boolean?} full - Include timestamp.
 */

NetworkAddress.prototype.fromReader = function fromReader(br, full) {
  // only version >= 31402
  this.ts = full ? br.readU32() : 0;
  this.services = br.readU53();
  this.host = IP.toString(br.readBytes(16));
  this.port = br.readU16BE();

  this.hostname = IP.hostname(this.host, this.port);

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @param {Boolean?} full - Include timestamp.
 */

NetworkAddress.prototype.fromRaw = function fromRaw(data, full) {
  return this.fromReader(new BufferReader(data), full);
};

/**
 * Insantiate a network address from buffer reader.
 * @param {BufferReader} br
 * @param {Boolean?} full - Include timestamp.
 * @returns {NetworkAddress}
 */

NetworkAddress.fromReader = function fromReader(br, full) {
  return new NetworkAddress().fromReader(br, full);
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
 * Write network address to a buffer writer.
 * @param {BufferWriter} bw
 * @param {Boolean?} full - Include timestamp.
 * @returns {Buffer}
 */

NetworkAddress.prototype.toWriter = function toWriter(bw, full) {
  if (full)
    bw.writeU32(this.ts);

  bw.writeU64(this.services);
  bw.writeBytes(IP.toBuffer(this.host));
  bw.writeU16BE(this.port);

  return bw;
};

/**
 * Calculate serialization size of address.
 * @returns {Number}
 */

NetworkAddress.prototype.getSize = function getSize(full) {
  return 26 + (full ? 4 : 0);
};

/**
 * Serialize network address.
 * @param {Boolean?} full - Include timestamp.
 * @returns {Buffer}
 */

NetworkAddress.prototype.toRaw = function toRaw(full) {
  var size = this.getSize(full);
  return this.toWriter(new StaticWriter(size), full).render();
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
    + ' date=' + util.date(this.ts)
    + '>';
};

/*
 * Expose
 */

module.exports = NetworkAddress;
