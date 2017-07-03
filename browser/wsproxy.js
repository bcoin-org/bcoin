'use strict';

const net = require('net');
const EventEmitter = require('events').EventEmitter;
const IOServer = require('socket.io');
const util = require('../lib/utils/util');
const digest = require('../lib/crypto/digest');
const IP = require('../lib/utils/ip');
const BufferWriter = require('../lib/utils/writer');

const NAME_REGEX = /^[a-z0-9\-\.]+?\.(?:be|me|org|com|net|ch|de)$/i;

const TARGET = Buffer.from(
  '0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex');

function WSProxy(options) {
  if (!(this instanceof WSProxy))
    return new WSProxy(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.target = options.target || TARGET;
  this.pow = options.pow === true;
  this.ports = options.ports || [];
  this.io = new IOServer();
  this.sockets = new WeakMap();

  this._init();
}

util.inherits(WSProxy, EventEmitter);

WSProxy.prototype._init = function _init() {
  this.io.on('error', (err) => {
    this.emit('error', err);
  });

  this.io.on('connection', (ws) => {
    this._handleSocket(ws);
  });
};

WSProxy.prototype._handleSocket = function _handleSocket(ws) {
  let state = new SocketState(this, ws);

  // Use a weak map to avoid
  // mutating the websocket object.
  this.sockets.set(ws, state);

  ws.emit('info', state.toInfo());

  ws.on('error', (err) => {
    this.emit('error', err);
  });

  ws.on('tcp connect', (port, host, nonce) => {
    this._handleConnect(ws, port, host, nonce);
  });
};

WSProxy.prototype._handleConnect = function _handleConnect(ws, port, host, nonce) {
  let state = this.sockets.get(ws);
  let socket, pow, raw;

  if (state.socket) {
    this.log('Client is trying to reconnect (%s).', state.host);
    return;
  }

  if (!util.isNumber(port)
      || typeof host !== 'string'
      || host.length === 0) {
    this.log('Client gave bad arguments (%s).', state.host);
    ws.emit('tcp close');
    ws.disconnect();
    return;
  }

  if (this.pow) {
    if (!util.isNumber(nonce)) {
      this.log('Client did not solve proof of work (%s).', state.host);
      ws.emit('tcp close');
      ws.disconnect();
      return;
    }

    pow = new BufferWriter();
    pow.writeU32(nonce);
    pow.writeBytes(state.snonce);
    pow.writeU32(port);
    pow.writeString(host, 'ascii');
    pow = pow.render();

    if (digest.hash256(pow).compare(this.target) > 0) {
      this.log('Client did not solve proof of work (%s).', state.host);
      ws.emit('tcp close');
      ws.disconnect();
      return;
    }
  }

  try {
    raw = IP.toBuffer(host);
    host = IP.toString(raw);
  } catch (e) {
    this.log('Client gave a bad host: %s (%s).', host, state.host);
    ws.emit('tcp error', {
      message: 'EHOSTUNREACH',
      code: 'EHOSTUNREACH'
    });
    ws.disconnect();
    return;
  }

  if (!IP.isRoutable(raw) || IP.isOnion(raw)) {
    this.log(
      'Client is trying to connect to a bad ip: %s (%s).',
      host, state.host);
    ws.emit('tcp error', {
      message: 'ENETUNREACH',
      code: 'ENETUNREACH'
    });
    ws.disconnect();
    return;
  }

  if (this.ports.indexOf(port) === -1) {
    this.log('Client is connecting to non-whitelist port (%s).', state.host);
    ws.emit('tcp error', {
      message: 'ENETUNREACH',
      code: 'ENETUNREACH'
    });
    ws.disconnect();
    return;
  }

  try {
    socket = state.connect(port, host);
    this.log('Connecting to %s (%s).', state.remoteHost, state.host);
  } catch (e) {
    this.log(e.message);
    this.log('Closing %s (%s).', state.remoteHost, state.host);
    ws.emit('tcp error', {
      message: 'ENETUNREACH',
      code: 'ENETUNREACH'
    });
    ws.disconnect();
    return;
  }

  socket.on('connect', () => {
    ws.emit('tcp connect', socket.remoteAddress, socket.remotePort);
  });

  socket.on('data', (data) => {
    ws.emit('tcp data', data.toString('hex'));
  });

  socket.on('error', (err) => {
    ws.emit('tcp error', {
      message: err.message,
      code: err.code || null
    });
  });

  socket.on('timeout', () => {
    ws.emit('tcp timeout');
  });

  socket.on('close', () => {
    this.log('Closing %s (%s).', state.remoteHost, state.host);
    ws.emit('tcp close');
    ws.disconnect();
  });

  ws.on('tcp data', (data) => {
    if (typeof data !== 'string')
      return;
    socket.write(Buffer.from(data, 'hex'));
  });

  ws.on('tcp keep alive', (enable, delay) => {
    socket.setKeepAlive(enable, delay);
  });

  ws.on('tcp no delay', (enable) => {
    socket.setNoDelay(enable);
  });

  ws.on('tcp set timeout', (timeout) => {
    socket.setTimeout(timeout);
  });

  ws.on('tcp pause', () => {
    socket.pause();
  });

  ws.on('tcp resume', () => {
    socket.resume();
  });

  ws.on('disconnect', () => {
    socket.destroy();
  });
};

WSProxy.prototype.log = function log(...args) {
  process.stdout.write('wsproxy: ');
  console.log(...args);
};

WSProxy.prototype.attach = function attach(server) {
  this.io.attach(server);
};

function SocketState(server, socket) {
  this.pow = server.pow;
  this.target = server.target;
  this.snonce = util.nonce();
  this.socket = null;
  this.host = IP.normalize(socket.conn.remoteAddress);
  this.remoteHost = null;
}

SocketState.prototype.toInfo = function toInfo() {
  return {
    pow: this.pow,
    target: this.target.toString('hex'),
    snonce: this.snonce.toString('hex')
  };
};

SocketState.prototype.connect = function connect(port, host) {
  this.socket = net.connect(port, host);
  this.remoteHost = IP.toHostname(host, port);
  return this.socket;
};

module.exports = WSProxy;
