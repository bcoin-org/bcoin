/*!
 * socks.js - socks proxy for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const net = require('net');
const {format} = require('util');
const IP = require('binet');

/**
 * SOCKS State Machine
 * @extends EventEmitter
 */

class SOCKS extends EventEmitter {
  /**
   * Create a SOCKS context.
   * @constructor
   */

  constructor() {
    super();

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

  error(err) {
    if (this.destroyed)
      return;

    if (err instanceof Error) {
      this.emit('error', err);
      this.destroy();
      return;
    }

    const msg = format.apply(null, arguments);
    this.emit('error', new Error(msg));
    this.destroy();
  }

  getError(code) {
    if (code >= SOCKS.errors.length)
      return SOCKS.errors[9];

    return SOCKS.errors[code];
  }

  destroy() {
    if (this.destroyed)
      return;

    this.destroyed = true;
    this.socket.destroy();

    this.stopTimeout();

    if (this.state === this.target)
      return;

    this.emit('close');
  }

  startTimeout() {
    this.timeout = setTimeout(() => {
      const state = SOCKS.statesByVal[this.state];
      this.timeout = null;
      this.error('SOCKS request timed out (state=%s).', state);
    }, 8000);
  }

  stopTimeout() {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
  }

  connect(port, host) {
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
  }

  open(options) {
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
  }

  proxy(options) {
    assert(options);
    assert(typeof options.destHost === 'string');
    assert(typeof options.destPort === 'number');

    this.destHost = options.destHost;
    this.destPort = options.destPort;
    this.target = SOCKS.states.PROXY_DONE;

    this.open(options);
  }

  resolve(options) {
    assert(options);
    assert(typeof options.name === 'string');

    this.name = options.name;
    this.target = SOCKS.states.RESOLVE_DONE;

    this.open(options);
  }

  handleConnect() {
    assert(this.state === SOCKS.states.CONNECT);
    this.sendHandshake();
  }

  handleError(err) {
    this.error(err);
  }

  handleClose() {
    if (this.state !== this.target) {
      const state = SOCKS.statesByVal[this.state];
      this.error('SOCKS request destroyed (state=%s).', state);
      return;
    }

    this.destroy();
  }

  handleData(data) {
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
  }

  sendHandshake() {
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
  }

  handleHandshake(data) {
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
  }

  sendAuth() {
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

    const packet = Buffer.allocUnsafe(size);

    packet[0] = 0x01;
    packet[1] = ulen;
    packet.write(user, 2, ulen, 'ascii');
    packet[2 + ulen] = plen;
    packet.write(pass, 2 + ulen, plen, 'ascii');

    this.state = SOCKS.states.AUTH;
    this.socket.write(packet);
  }

  handleAuth(data) {
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
  }

  auth() {
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
  }

  sendProxy() {
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

    const packet = Buffer.allocUnsafe(6 + len);

    let off = 0;

    packet[off++] = 0x05;
    packet[off++] = 0x01;
    packet[off++] = 0x00;
    packet[off++] = type;

    if (type === 0x03)
      packet[off++] = name.length;

    off += name.copy(packet, off);
    packet.writeUInt32BE(port, off);

    this.state = SOCKS.states.PROXY;
    this.socket.write(packet);
  }

  handleProxy(data) {
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
  }

  sendResolve() {
    const name = this.name;
    const len = Buffer.byteLength(name, 'utf8');

    const packet = Buffer.allocUnsafe(7 + len);

    packet[0] = 0x05;
    packet[1] = 0xf0;
    packet[2] = 0x00;
    packet[3] = 0x03;
    packet[4] = len;
    packet.write(name, 5, len, 'utf8');
    packet.writeUInt32BE(0, 5 + len);

    this.state = SOCKS.states.RESOLVE;
    this.socket.write(packet);
  }

  handleResolve(data) {
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
  }

  static resolve(options) {
    const socks = new SOCKS();
    return new Promise((resolve, reject) => {
      socks.resolve(options);
      socks.on('resolve', resolve);
      socks.on('error', reject);
    });
  }

  static proxy(options) {
    const socks = new SOCKS();
    return new Promise((resolve, reject) => {
      socks.proxy(options);
      socks.on('proxy', resolve);
      socks.on('error', reject);
    });
  }
}

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

SOCKS.statesByVal = [
  'INIT',
  'CONNECT',
  'HANDSHAKE',
  'AUTH',
  'PROXY',
  'PROXY_DONE',
  'RESOLVE',
  'RESOLVE_DONE'
];

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

/**
 * Proxy Socket
 * @extends EventEmitter
 */

class ProxySocket extends EventEmitter {
  /**
   * Create a proxy socket.
   * @constructor
   * @param {String} host
   * @param {Number} port
   * @param {String?} user
   * @param {String?} pass
   */

  constructor(host, port, user, pass) {
    super();

    assert(typeof host === 'string');
    assert(typeof port === 'number');

    this.socket = null;
    this.host = host;
    this.port = port;
    this.username = user || null;
    this.password = pass || null;
    this.remoteAddress = '127.0.0.1';
    this.remoteFamily = 'IPv4';
    this.remotePort = 0;
    this.ops = [];
  }

  get encrypted() {
    if (!this.socket)
      return false;
    return this.socket.encrypted || false;
  }

  get readable() {
    if (!this.socket)
      return false;
    return this.socket.readable;
  }

  get writable() {
    if (!this.socket)
      return false;
    return this.socket.writable;
  }

  get destroyed() {
    if (!this.socket)
      return false;
    return this.socket.destroyed;
  }

  get connecting() {
    if (!this.socket)
      return false;
    return this.socket.connecting;
  }

  get bufferSize() {
    if (!this.socket)
      return 0;
    return this.socket.bufferSize;
  }

  get bytesWritten() {
    if (!this.socket)
      return 0;
    return this.socket.bytesWritten;
  }

  get bytesRead() {
    if (!this.socket)
      return 0;
    return this.socket.bytesRead;
  }

  get localAddress() {
    if (!this.socket)
      return '127.0.0.1';
    return this.socket.localAddress;
  }

  get localPort() {
    if (!this.socket)
      return 0;
    return this.socket.localPort;
  }

  async connect(port, host) {
    assert(!this.socket, 'Already connected.');

    if (!host)
      host = '127.0.0.1';

    const options = {
      host: this.host,
      port: this.port,
      username: this.username,
      password: this.password,
      destHost: host,
      destPort: port
    };

    const type = IP.getStringType(host);

    this.remoteAddress = host;
    this.remoteFamily = type === IP.types.IPV6 ? 'IPv6' : 'IPv4';
    this.remotePort = port;

    let socket;
    try {
      socket = await SOCKS.proxy(options);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.socket = socket;

    this.socket.on('error', (err) => {
      this.emit('error', err);
    });

    this.socket.on('close', () => {
      this.emit('close');
    });

    this.socket.on('data', (data) => {
      this.emit('data', data);
    });

    this.socket.on('drain', () => {
      this.emit('drain');
    });

    this.socket.on('timeout', () => {
      this.emit('timeout');
    });

    for (const op of this.ops)
      op();

    this.ops.length = 0;

    this.emit('connect');
  }

  setKeepAlive(enable, delay) {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.setKeepAlive(enable, delay);
      });
      return this;
    }
    this.socket.setKeepAlive(enable, delay);
    return this;
  }

  setNoDelay(enable) {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.setNoDelay(enable);
      });
      return this;
    }
    this.socket.setNoDelay(enable);
    return this;
  }

  setTimeout(timeout, callback) {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.setTimeout(timeout, callback);
      });
      return this;
    }
    this.socket.setTimeout(timeout, callback);
    return this;
  }

  setEncoding(enc) {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.setEncoding(enc);
      });
      return this;
    }
    this.socket.setEncoding(enc);
    return this;
  }

  address() {
    return {
      address: this.remoteAddress,
      family: this.remoteFamily,
      port: this.remotePort
    };
  }

  ref() {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.ref();
      });
      return this;
    }
    this.socket.ref();
    return this;
  }

  unref() {
    if (!this.socket) {
      this.ops.push(() => {
        this.socket.unref();
      });
      return this;
    }
    this.socket.unref();
    return this;
  }

  write(data, enc, callback) {
    if (!this.socket)
      return true;

    return this.socket.write(data, enc, callback);
  }

  end(data, enc) {
    if (!this.socket)
      return this;

    if (data != null)
      this.write(data, enc);

    this.socket.end();

    return this;
  }

  pause() {
    if (!this.socket)
      return this;

    this.socket.pause();

    return this;
  }

  resume() {
    if (!this.socket)
      return this;

    this.socket.resume();

    return this;
  }

  destroy(err) {
    if (!this.socket)
      return this;

    this.socket.destroy(err);

    return this;
  }
}

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

function parseAddr(data, off) {
  if (data.length - off < 2)
    throw new Error('Bad SOCKS address length.');

  const type = data[off];
  off += 1;

  let host, port;

  switch (type) {
    case 0x01: {
      if (data.length - off < 6)
        throw new Error('Bad SOCKS ipv4 length.');

      host = IP.toString(data.slice(off, off + 4));
      off += 4;

      port = data.readUInt16BE(off);
      break;
    }
    case 0x03: {
      const len = data[off];
      off += 1;

      if (data.length - off < len + 2)
        throw new Error('Bad SOCKS domain length.');

      host = data.toString('utf8', off, off + len);
      off += len;

      port = data.readUInt16BE(off);
      break;
    }
    case 0x04: {
      if (data.length - off < 18)
        throw new Error('Bad SOCKS ipv6 length.');

      host = IP.toString(data.slice(off, off + 16));
      off += 16;

      port = data.readUInt16BE(off);
      break;
    }
    default: {
      throw new Error(`Unknown SOCKS address type: ${type}.`);
    }
  }

  return { type, host, port };
}

/*
 * Expose
 */

exports.unsupported = false;

exports.connect = function connect(proxy, destPort, destHost) {
  const addr = parseProxy(proxy);
  const host = addr.host;
  const port = addr.port;
  const user = addr.username;
  const pass = addr.password;

  const socket = new ProxySocket(host, port, user, pass);
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
