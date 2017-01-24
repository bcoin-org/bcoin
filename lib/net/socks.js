/*!
 * socks.js - socks proxy for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var net = require('net');
var util = require('../utils/util');
var co = require('../utils/co');
var IP = require('../utils/ip');
var StaticWriter = require('../utils/staticwriter');
var BufferReader = require('../utils/reader');

/**
 * SOCKS state machine
 * @constructor
 */

function SOCKS() {
  if (!(this instanceof SOCKS))
    return new SOCKS();

  EventEmitter.call(this);

  this.socket = new net.Socket();
  this.state = SOCKS.states.INIT;
  this.target = SOCKS.states.INIT;
  this.destHost = '0.0.0.0';
  this.destPort = 0;
  this.username = '';
  this.password = '';
  this.name = 'localhost';
  this.destroyed = false;
  this.timeout = null;
  this.proxied = false;
}

util.inherits(SOCKS, EventEmitter);

SOCKS.states = {
  INIT: 0,
  CONNECT: 1,
  HANDSHAKE: 2,
  AUTH: 3,
  PROXY: 4,
  PROXY_DONE: 5,
  RESOLVE: 6,
  RESOLVE_DONE: 7
};

SOCKS.prototype.error = function error(msg) {
  if (this.destroyed)
    return;

  if (msg instanceof Error) {
    this.emit('error', msg);
    this.destroy();
    return;
  }

  this.emit('error', new Error(msg));
  this.destroy();
};

SOCKS.prototype.destroy = function destroy() {
  if (this.destroyed)
    return;

  this.destroyed = true;
  this.socket.destroy();

  this.stopTimeout();

  if (this.state === this.target)
    return;

  this.emit('close');
};

SOCKS.prototype.startTimeout = function startTimeout() {
  var self = this;
  this.timeout = setTimeout(function() {
    self.timeout = null;
    self.error('Request timed out (' + self.state + ').');
  }, 5000);
};

SOCKS.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

SOCKS.prototype.connect = function connect(port, host) {
  var self = this;

  assert(typeof port === 'number');
  assert(typeof host === 'string');

  this.state = SOCKS.states.CONNECT;
  this.socket.connect(port, host);

  this.socket.on('connect', function() {
    if (self.proxied)
      return;
    self.handleConnect();
  });

  this.socket.on('data', function(data) {
    if (self.proxied)
      return;
    self.handleData(data);
  });

  this.socket.on('error', function(err) {
    if (self.proxied)
      return;
    self.handleError(err);
  });

  this.socket.on('close', function() {
    if (self.proxied)
      return;
    self.handleClose();
  });
};

SOCKS.prototype.open = function open(options) {
  assert(this.state === SOCKS.states.INIT);

  assert(options);

  if (options.username != null) {
    assert(typeof options.username === 'string');
    this.username = options.username;
  }

  if (options.password != null) {
    assert(typeof options.password === 'string');
    this.password = options.password;
  }

  this.startTimeout();
  this.connect(options.port, options.host);
};

SOCKS.prototype.proxy = function proxy(options) {
  assert(options);
  assert(typeof options.destHost === 'string');
  assert(typeof options.destPort === 'number');

  this.destHost = options.destHost;
  this.destPort = options.destPort;
  this.target = SOCKS.states.PROXY_DONE;

  this.open(options);
};

SOCKS.prototype.resolve = function resolve(options) {
  assert(options);
  assert(typeof options.name === 'string');

  this.name = options.name;
  this.target = SOCKS.states.RESOLVE_DONE;

  this.open(options);
};

SOCKS.prototype.handleConnect = function handleConnect() {
  assert(this.state === SOCKS.states.CONNECT);
  this.sendHandshake();
};

SOCKS.prototype.handleError = function handleError(err) {
  this.error(err);
};

SOCKS.prototype.handleClose = function handleClose() {
  if (this.state !== this.target) {
    this.error('State did not reach target state of: ' + this.target);
    return;
  }

  this.destroy();
};

SOCKS.prototype.handleData = function handleData(data) {
  switch (this.state) {
    case SOCKS.states.INIT:
      this.error('Data before connection.');
      break;
    case SOCKS.states.CONNECT:
      this.error('Data before handshake.');
      break;
    case SOCKS.states.HANDSHAKE:
      this.handleHandshake(data);
      break;
    case SOCKS.states.AUTH:
      this.handleAuth(data);
      break;
    case SOCKS.states.PROXY:
      this.handleProxy(data);
      break;
    case SOCKS.states.RESOLVE:
      this.handleResolve(data);
      break;
    case SOCKS.states.PROXY_DONE:
    case SOCKS.states.RESOLVE_DONE:
      break;
    default:
      assert(false, 'Bad state.');
      break;
  }
};

SOCKS.prototype.sendHandshake = function sendHandshake() {
  var packet;

  if (this.username) {
    packet = new Buffer(4);
    packet[0] = 0x05;
    packet[1] = 0x02;
    packet[2] = 0x00;
    packet[3] = 0x02;
  } else {
    packet = new Buffer(3);
    packet[0] = 0x05;
    packet[1] = 0x01;
    packet[2] = 0x00;
  }

  this.state = SOCKS.states.HANDSHAKE;
  this.socket.write(packet);
};

SOCKS.prototype.handleHandshake = function handleHandshake(data) {
  if (data.length !== 2) {
    this.error('Bad handshake response.');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version.');
    return;
  }

  this.emit('handshake');

  switch (data[1]) {
    case 0xff:
      this.error('No acceptable auth methods.');
      break;
    case 0x02:
      this.sendAuth();
      break;
    case 0x00:
      this.state = SOCKS.states.AUTH;
      this.auth();
      break;
    default:
      this.error('Handshake error: ' + data[1]);
      break;
  }
};

SOCKS.prototype.sendAuth = function sendAuth() {
  var user = this.username;
  var pass = this.password;
  var ulen, plen, size, packet;

  if (!user) {
    this.error('No username passed for auth.');
    return;
  }

  if (!pass) {
    this.error('No password passed for auth.');
    return;
  }

  ulen = Buffer.byteLength(user, 'ascii');
  plen = Buffer.byteLength(pass, 'ascii');
  size = 3 + ulen + plen;

  packet = new StaticWriter(size);
  packet.writeU8(0x01);
  packet.writeU8(ulen);
  packet.writeString(user, 'ascii');
  packet.writeU8(plen);
  packet.writeString(pass, 'ascii');
  packet = packet.render();

  this.state = SOCKS.states.AUTH;
  this.socket.write(packet);
};

SOCKS.prototype.handleAuth = function handleAuth(data) {
  if (data.length !== 2) {
    this.error('Bad auth response.');
    return;
  }

  if (data[0] !== 0x01) {
    this.error('Bad version number.');
    return;
  }

  if (data[1] !== 0x00) {
    this.error('Auth failure: ' + data[0]);
    return;
  }

  this.auth();
};

SOCKS.prototype.auth = function auth() {
  this.emit('auth');

  switch (this.target) {
    case SOCKS.states.PROXY_DONE:
      this.sendProxy();
      break;
    case SOCKS.states.RESOLVE_DONE:
      this.sendResolve();
      break;
    default:
      this.error('Bad target state.');
      break;
  }
};

SOCKS.prototype.sendProxy = function sendProxy() {
  var host = this.destHost;
  var port = this.destPort;
  var ip, len, type, name, packet;

  switch (IP.getStringType(host)) {
    case IP.types.IPV4:
      ip = IP.toBuffer(host);
      type = 0x01;
      name = ip.slice(12, 16);
      len = 4;
      break;
    case IP.types.IPV6:
      ip = IP.toBuffer(host);
      type = 0x04;
      name = ip;
      len = 16;
      break;
    default:
      type = 0x03;
      name = new Buffer(host, 'ascii');
      len = 1 + name.length;
      break;
  }

  packet = new StaticWriter(6 + len);

  packet.writeU8(0x05);
  packet.writeU8(0x01);
  packet.writeU8(0x00);
  packet.writeU8(type);

  if (type === 0x03)
    packet.writeU8(name.length);

  packet.writeBytes(name);
  packet.writeU16BE(port);

  packet = packet.render();

  this.state = SOCKS.states.PROXY;
  this.socket.write(packet);
};

SOCKS.prototype.handleProxy = function handleProxy(data) {
  var br, len, host, port;

  if (data.length < 6) {
    this.error('Setup failed.');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version.');
    return;
  }

  switch (data[1]) {
    case 0x00:
      break;
    case 0x01:
      this.error('General failure.');
      return;
    case 0x02:
      this.error('Connection not allowed.');
      return;
    case 0x03:
      this.error('Network is unreachable.');
      return;
    case 0x04:
      this.error('Host is unreachable.');
      return;
    case 0x05:
      this.error('Connection refused.');
      return;
    case 0x06:
      this.error('TTL expired.');
      return;
    case 0x07:
      this.error('Command not supported.');
      return;
    case 0x08:
      this.error('Address type not supported.');
      return;
    default:
      this.error('Unknown proxy error: ' + data[1]);
      return;
  }

  if (data[2] !== 0x00) {
    this.error('Data corruption.');
    return;
  }

  br = new BufferReader(data);
  br.seek(3);

  switch (br.readU8()) {
    case 0x01:
      if (br.left() < 6) {
        this.error('Bad packet length.');
        return;
      }
      host = IP.toString(br.readBytes(4));
      port = br.readU16BE();
      break;
    case 0x03:
      len = br.readU8();
      if (br.left() < len + 2) {
        this.error('Bad packet length.');
        return;
      }
      host = br.readString(len, 'utf8');
      port = br.readU16BE();
      break;
    case 0x04:
      if (br.left() < 18) {
        this.error('Bad packet length.');
        return;
      }
      host = IP.toString(br.readBytes(16));
      port = br.readU16BE();
      break;
    default:
      this.error('Unknown response.');
      return;
  }

  this.state = SOCKS.states.PROXY_DONE;
  this.stopTimeout();
  this.proxied = true;

  this.emit('proxy', this.socket);
};

SOCKS.prototype.sendResolve = function sendResolve() {
  var name = this.name;
  var len = Buffer.byteLength(name, 'utf8');
  var packet = new StaticWriter(7 + len);

  packet.writeU8(0x05);
  packet.writeU8(0xf0);
  packet.writeU8(0x00);
  packet.writeU8(0x03);
  packet.writeU8(len);
  packet.writeString(name, 'utf8');
  packet.writeU16BE(0);
  packet = packet.render();

  this.state = SOCKS.states.RESOLVE;
  this.socket.write(packet);
};

SOCKS.prototype.handleResolve = function handleResolve(data) {
  var ip;

  if (data.length !== 10) {
    this.error('Resolve failed.');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version.');
    return;
  }

  if (data[1] !== 0x00) {
    this.error('Tor error: ' + data[1]);
    return;
  }

  if (data[2] !== 0x00) {
    this.error('Tor error: ' + data[2]);
    return;
  }

  if (data[3] !== 0x01) {
    this.error('Tor error.');
    return;
  }

  try {
    ip = IP.toString(data.slice(4, 8));
  } catch (e) {
    this.error(e);
    return;
  }

  this.state = SOCKS.states.RESOLVE_DONE;

  this.destroy();

  this.emit('resolve', [ip]);
};

SOCKS.resolve = function resolve(options) {
  var socks = new SOCKS();
  return new Promise(function(resolve, reject) {
    socks.resolve(options);
    socks.on('resolve', resolve);
    socks.on('error', reject);
  });
};

SOCKS.proxy = function proxy(options) {
  var socks = new SOCKS();
  return new Promise(function(resolve, reject) {
    socks.proxy(options);
    socks.on('proxy', resolve);
    socks.on('error', reject);
  });
};

/**
 * Proxy Socket
 * @constructor
 * @param {String} proxy
 * @param {String?} user
 * @param {String?} pass
 */

function Proxy(proxy, user, pass) {
  if (!(this instanceof Proxy))
    return new Proxy(proxy, user, pass);

  EventEmitter.call(this);

  this.socket = null;
  this.proxy = IP.fromHostname(proxy);
  this.username = user;
  this.password = pass;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this.remoteAddress = null;
  this.remotePort = 0;
}

util.inherits(Proxy, EventEmitter);

Proxy.prototype.connect = co(function* connect(port, host) {
  var self = this;
  var options, socket;

  options = {
    host: this.proxy.host,
    port: this.proxy.port,
    username: this.username,
    password: this.password,
    destHost: host,
    destPort: port
  };

  try {
    socket = yield SOCKS.proxy(options);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  this.remoteAddress = host;
  this.remotePort = port;
  this.socket = socket;

  this.socket.on('error', function(err) {
    self.emit('error', err);
  });

  this.socket.on('close', function() {
    self.emit('close');
  });

  this.socket.on('data', function(data) {
    self.bytesRead += data.length;
    self.emit('data', data);
  });

  this.socket.on('drain', function() {
    self.emit('drain');
  });

  this.emit('connect');
});

Proxy.prototype.write = function write(data, callback) {
  this.bytesWritten += data.length;
  return this.socket.write(data, callback);
};

Proxy.prototype.end = function end() {
  return this.socket.end();
};

Proxy.prototype.pause = function pause() {
  return this.socket.pause();
};

Proxy.prototype.resume = function resume() {
  return this.socket.resume();
};

Proxy.prototype.destroy = function destroy() {
  return this.socket.destroy();
};

/*
 * Expose
 */

exports.connect = function connect(proxy, port, host, user, pass) {
  var socket = new Proxy(proxy, user, pass);
  socket.connect(port, host);
  return socket;
};

exports.resolve = function resolve(proxy, name, user, pass) {
  var addr = IP.fromHostname(proxy);
  return SOCKS.resolve({
    host: addr.host,
    port: addr.port,
    username: user,
    password: pass,
    name: name
  });
};
