/*!
 * netaddress.js - network address object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

module.exports = NetworkAddress;

var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var time = require('../net/timedata');
var utils = require('../utils/utils');
var IP = require('../utils/ip');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
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

  network = Network.get(network);

  this.host = address.host;
  this.port = address.port || network.port;
  this.services = constants.services.NETWORK
    | constants.services.BLOOM
    | constants.services.WITNESS;
  this.ts = time.now();

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
  this.ts = time.now();

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
  var p = BufferReader(data);
  var now = time.now();

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
  var p = BufferWriter(writer);

  if (full)
    p.writeU32(this.ts);

  p.writeU64(this.services);
  p.writeBytes(IP.toBuffer(this.host));
  p.writeU16BE(this.port);

  if (!writer)
    p = p.render();

  return p;
};

/*
 * Expose
 */

module.exports = NetworkAddress;
