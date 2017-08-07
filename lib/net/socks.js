/*!
 * socks.js - socks proxy for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/socks
 */

const assert = require('assert');
const EventEmitter = require('events');
const net = require('net');
const util = require('../utils/util');
const IP = require('../utils/ip');
const StaticWriter = require('../utils/staticwriter');
const BufferReader = require('../utils/reader');

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

Object.setPrototypeOf(SOCKS.prototype, EventEmitter.prototype);

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

SOCKS.statesByVal = util.reverse(SOCKS.states);

SOCKS.errors = [
  '',
  'General failure',
  'Connection not allowed',
  'Network is unreachable',
  'Host is unreachable',
  'Connection refused',
  'TTL expired',
  'Command not supported',
  'Address type not supported',
  'Unknown proxy error'
];

SOCKS.prototype.error = function error(err) {
  if (this.destroyed)
    return;

  if (err instanceof Error) {
    this.emit('error', err);
    this.destroy();
    return;
  }

  const msg = util.fmt.apply(util, arguments);
  this.emit('error', new Error(msg));
  this.destroy();
};

SOCKS.prototype.getError = function getError(code) {
  if (code >= SOCKS.errors.length)
    return SOCKS.errors[9];

  return SOCKS.errors[code];
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
  this.timeout = setTimeout(() => {
    const state = SOCKS.statesByVal[this.state];
    this.timeout = null;
    this.error('SOCKS request timed out (state=%s).', state);
  }, 8000);
};

SOCKS.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

SOCKS.prototype.connect = function connect(port, host) {
  assert(typeof port === 'number');
  assert(typeof host === 'string');

  this.state = SOCKS.states.CONNECT;
  this.socket.connect(port, host);

  this.socket.on('connect', () => {
    if (this.proxied)
      return;
    this.handleConnect();
  });

  this.socket.on('data', (data) => {
    if (this.proxied)
      return;
    this.handleData(data);
  });

  this.socket.on('error', (err) => {
    if (this.proxied)
      return;
    this.handleError(err);
  });

  this.socket.on('close', () => {
    if (this.proxied)
      return;
    this.handleClose();
  });
};

SOCKS.prototype.open = function open(options) {
  assert(this.state === SOCKS.states.INIT);

  assert(options);

  if (options.username != null) {
    assert(typeof options.username === 'string');
    this.username = options.username;
    assert(typeof options.password === 'string',
      'Username must have a password.');
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
    const state = SOCKS.statesByVal[this.state];
    this.error('SOCKS request destroyed (state=%s).', state);
    return;
  }

  this.destroy();
};

SOCKS.prototype.handleData = function handleData(data) {
  switch (this.state) {
    case SOCKS.states.INIT:
      this.error('Data before SOCKS connection.');
      break;
    case SOCKS.states.CONNECT:
      this.error('Data before SOCKS handshake.');
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
  let packet;

  if (this.username) {
    packet = Buffer.allocUnsafe(4);
    packet[0] = 0x05;
    packet[1] = 0x02;
    packet[2] = 0x00;
    packet[3] = 0x02;
  } else {
    packet = Buffer.allocUnsafe(3);
    packet[0] = 0x05;
    packet[1] = 0x01;
    packet[2] = 0x00;
  }

  this.state = SOCKS.states.HANDSHAKE;
  this.socket.write(packet);
};

SOCKS.prototype.handleHandshake = function handleHandshake(data) {
  if (data.length !== 2) {
    this.error('Bad SOCKS handshake response (size).');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version for handshake.');
    return;
  }

  this.emit('handshake');

  switch (data[1]) {
    case 0xff:
      this.error('No acceptable SOCKS auth methods.');
      break;
    case 0x02:
      this.sendAuth();
      break;
    case 0x00:
      this.state = SOCKS.states.AUTH;
      this.auth();
      break;
    default:
      this.error('SOCKS handshake error: %d.', data[1]);
      break;
  }
};

SOCKS.prototype.sendAuth = function sendAuth() {
  const user = this.username;
  const pass = this.password;

  if (!user) {
    this.error('No username passed for SOCKS auth.');
    return;
  }

  if (!pass) {
    this.error('No password passed for SOCKS auth.');
    return;
  }

  const ulen = Buffer.byteLength(user, 'ascii');
  const plen = Buffer.byteLength(pass, 'ascii');
  const size = 3 + ulen + plen;

  const bw = new StaticWriter(size);

  bw.writeU8(0x01);
  bw.writeU8(ulen);
  bw.writeString(user, 'ascii');
  bw.writeU8(plen);
  bw.writeString(pass, 'ascii');

  const packet = bw.render();

  this.state = SOCKS.states.AUTH;
  this.socket.write(packet);
};

SOCKS.prototype.handleAuth = function handleAuth(data) {
  if (data.length !== 2) {
    this.error('Bad packet size for SOCKS auth.');
    return;
  }

  if (data[0] !== 0x01) {
    this.error('Bad SOCKS auth version number.');
    return;
  }

  if (data[1] !== 0x00) {
    this.error('SOCKS auth failure: %d.', data[0]);
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
  const host = this.destHost;
  const port = this.destPort;
  let ip, len, type, name;

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
      name = Buffer.from(host, 'ascii');
      len = 1 + name.length;
      break;
  }

  const bw = new StaticWriter(6 + len);

  bw.writeU8(0x05);
  bw.writeU8(0x01);
  bw.writeU8(0x00);
  bw.writeU8(type);

  if (type === 0x03)
    bw.writeU8(name.length);

  bw.writeBytes(name);
  bw.writeU16BE(port);

  const packet = bw.render();

  this.state = SOCKS.states.PROXY;
  this.socket.write(packet);
};

SOCKS.prototype.handleProxy = function handleProxy(data) {
  if (data.length < 6) {
    this.error('Bad packet size for SOCKS connect.');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version for connect.');
    return;
  }

  if (data[1] !== 0x00) {
    const msg = this.getError(data[1]);
    this.error('SOCKS connect error: %s.', msg);
    return;
  }

  if (data[2] !== 0x00) {
    this.error('SOCKS connect failed (padding).');
    return;
  }

  let addr;
  try {
    addr = parseAddr(data, 3);
  } catch (e) {
    this.error(e);
    return;
  }

  this.state = SOCKS.states.PROXY_DONE;
  this.stopTimeout();
  this.proxied = true;

  this.emit('proxy address', addr);
  this.emit('proxy', this.socket);
};

SOCKS.prototype.sendResolve = function sendResolve() {
  const name = this.name;
  const len = Buffer.byteLength(name, 'utf8');

  const bw = new StaticWriter(7 + len);

  bw.writeU8(0x05);
  bw.writeU8(0xf0);
  bw.writeU8(0x00);
  bw.writeU8(0x03);
  bw.writeU8(len);
  bw.writeString(name, 'utf8');
  bw.writeU16BE(0);

  const packet = bw.render();

  this.state = SOCKS.states.RESOLVE;
  this.socket.write(packet);
};

SOCKS.prototype.handleResolve = function handleResolve(data) {
  if (data.length < 6) {
    this.error('Bad packet size for tor resolve.');
    return;
  }

  if (data[0] !== 0x05) {
    this.error('Bad SOCKS version for tor resolve.');
    return;
  }

  if (data[1] !== 0x00) {
    const msg = this.getError(data[1]);
    this.error('Tor resolve error: %s (%s).', msg, this.name);
    return;
  }

  if (data[2] !== 0x00) {
    this.error('Tor resolve failed (padding).');
    return;
  }

  let addr;
  try {
    addr = parseAddr(data, 3);
  } catch (e) {
    this.error(e);
    return;
  }

  if (addr.type === 0x03) {
    this.error('Bad address type for tor resolve.');
    return;
  }

  this.state = SOCKS.states.RESOLVE_DONE;
  this.destroy();

  this.emit('resolve', [addr.host]);
};

SOCKS.resolve = function resolve(options) {
  const socks = new SOCKS();
  return new Promise((resolve, reject) => {
    socks.resolve(options);
    socks.on('resolve', resolve);
    socks.on('error', reject);
  });
};

SOCKS.proxy = function proxy(options) {
  const socks = new SOCKS();
  return new Promise((resolve, reject) => {
    socks.proxy(options);
    socks.on('proxy', resolve);
    socks.on('error', reject);
  });
};

/**
 * Proxy Socket
 * @constructor
 * @param {String} host
 * @param {Number} port
 * @param {String?} user
 * @param {String?} pass
 */

function Proxy(host, port, user, pass) {
  if (!(this instanceof Proxy))
    return new Proxy(host, port, user, pass);

  EventEmitter.call(this);

  assert(typeof host === 'string');
  assert(typeof port === 'number');

  this.socket = null;
  this.host = host;
  this.port = port;
  this.username = user || null;
  this.password = pass || null;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this.remoteAddress = null;
  this.remotePort = 0;
  this.ops = [];
}

Object.setPrototypeOf(Proxy.prototype, EventEmitter.prototype);

Proxy.prototype.connect = async function connect(port, host) {
  assert(!this.socket, 'Already connected.');

  const options = {
    host: this.host,
    port: this.port,
    username: this.username,
    password: this.password,
    destHost: host,
    destPort: port
  };

  let socket;
  try {
    socket = await SOCKS.proxy(options);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  this.remoteAddress = host;
  this.remotePort = port;
  this.socket = socket;

  this.socket.on('error', (err) => {
    this.emit('error', err);
  });

  this.socket.on('close', () => {
    this.emit('close');
  });

  this.socket.on('data', (data) => {
    this.bytesRead += data.length;
    this.emit('data', data);
  });

  this.socket.on('drain', () => {
    this.emit('drain');
  });

  this.socket.on('timeout', () => {
    this.emit('timeout');
  });

  for (const op of this.ops)
    op.call(this);

  this.ops.length = 0;

  this.emit('connect');
};

Proxy.prototype.setKeepAlive = function setKeepAlive(enable, delay) {
  if (!this.socket) {
    this.ops.push(() => {
      this.socket.setKeepAlive(enable, delay);
    });
    return;
  }
  this.socket.setKeepAlive(enable, delay);
};

Proxy.prototype.setNoDelay = function setNoDelay(enable) {
  if (!this.socket) {
    this.ops.push(() => {
      this.socket.setNoDelay(enable);
    });
    return;
  }
  this.socket.setNoDelay(enable);
};

Proxy.prototype.setTimeout = function setTimeout(timeout, callback) {
  if (!this.socket) {
    this.ops.push(() => {
      this.socket.setTimeout(timeout, callback);
    });
    return;
  }
  this.socket.setTimeout(timeout, callback);
};

Proxy.prototype.write = function write(data, callback) {
  assert(this.socket, 'Not connected.');
  this.bytesWritten += data.length;
  return this.socket.write(data, callback);
};

Proxy.prototype.end = function end() {
  assert(this.socket, 'Not connected.');
  return this.socket.end();
};

Proxy.prototype.pause = function pause() {
  assert(this.socket, 'Not connected.');
  return this.socket.pause();
};

Proxy.prototype.resume = function resume() {
  assert(this.socket, 'Not connected.');
  return this.socket.resume();
};

Proxy.prototype.destroy = function destroy() {
  if (!this.socket)
    return;
  this.socket.destroy();
};

/*
 * Helpers
 */

function parseProxy(host) {
  const index = host.indexOf('@');

  if (index === -1) {
    const addr = IP.fromHostname(host, 1080);
    return {
      host: addr.host,
      port: addr.port
    };
  }

  const left = host.substring(0, index);
  const right = host.substring(index + 1);

  const parts = left.split(':');
  assert(parts.length > 1, 'Bad username and password.');

  const addr = IP.fromHostname(right, 1080);

  return {
    host: addr.host,
    port: addr.port,
    username: parts[0],
    password: parts[1]
  };
}

function parseAddr(data, offset) {
  const br = new BufferReader(data);

  if (br.left() < offset + 2)
    throw new Error('Bad SOCKS address length.');

  br.seek(offset);

  const type = br.readU8();
  let host, port;

  switch (type) {
    case 0x01: {
      if (br.left() < 6)
        throw new Error('Bad SOCKS ipv4 length.');

      host = IP.toString(br.readBytes(4));
      port = br.readU16BE();
      break;
    }
    case 0x03: {
      const len = br.readU8();

      if (br.left() < len + 2)
        throw new Error('Bad SOCKS domain length.');

      host = br.readString(len, 'utf8');
      port = br.readU16BE();
      break;
    }
    case 0x04: {
      if (br.left() < 18)
        throw new Error('Bad SOCKS ipv6 length.');

      host = IP.toString(br.readBytes(16));
      port = br.readU16BE();
      break;
    }
    default: {
      throw new Error(`Unknown SOCKS address type: ${type}.`);
    }
  }

  return {
    type: type,
    host: host,
    port: port
  };
}

/*
 * Expose
 */

exports.connect = function connect(proxy, destPort, destHost) {
  const addr = parseProxy(proxy);
  const host = addr.host;
  const port = addr.port;
  const user = addr.username;
  const pass = addr.password;

  const socket = new Proxy(host, port, user, pass);
  socket.connect(destPort, destHost);

  return socket;
};

exports.resolve = function resolve(proxy, name) {
  const addr = parseProxy(proxy);
  return SOCKS.resolve({
    host: addr.host,
    port: addr.port,
    username: addr.username,
    password: addr.password,
    name: name
  });
};
