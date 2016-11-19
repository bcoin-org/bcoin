'use strict';

var net = require('net');
var IOServer = require('socket.io');
var util = require('../lib/utils/util');
var IP = require('../lib/utils/ip');
var BufferWriter = require('../lib/utils/writer');
var EventEmitter = require('events').EventEmitter;

var TARGET = new Buffer(
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
  var self = this;

  this.io.on('error', function(err) {
    self.emit('error', err);
  });

  this.io.on('connection', function(ws) {
    self._handleSocket(ws);
  });
};

WSProxy.prototype._handleSocket = function _handleSocket(ws) {
  var self = this;
  var state = new SocketState(this, ws);

  // Use a weak map to avoid
  // mutating the websocket object.
  this.sockets.set(ws, state);

  ws.emit('info', state.toInfo());

  ws.on('error', function(err) {
    self.emit('error', err);
  });

  ws.on('tcp connect', function(port, host, nonce) {
    self._handleConnect(ws, port, host, nonce);
  });
};

WSProxy.prototype._handleConnect = function _handleConnect(ws, port, host, nonce) {
  var self = this;
  var state = this.sockets.get(ws);
  var socket, pow;

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
      this.log('Client did not solve proof of work.', state.host);
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

    if (util.cmp(util.hash256(pow), this.target) > 0) {
      this.log('Client did not solve proof of work (%s).', state.host);
      ws.emit('tcp close');
      ws.disconnect();
      return;
    }
  }

  if (!/^[a-zA-Z0-9\.:\-]+$/.test(host)) {
    this.log('Client gave a bad host (%s).', state.host);
    ws.emit('tcp error', {
      message: 'EHOSTUNREACH',
      code: 'EHOSTUNREACH'
    });
    ws.disconnect();
    return;
  }

  if (IP.isPrivate(host)) {
    this.log('Client is trying to connect to a private ip (%s).', state.host);
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

  socket.on('connect', function() {
    ws.emit('tcp connect');
  });

  socket.on('data', function(data) {
    ws.emit('tcp data', data.toString('hex'));
  });

  socket.on('error', function(err) {
    ws.emit('tcp error', {
      message: err.message,
      code: err.code || null
    });
  });

  socket.on('close', function() {
    self.log('Closing %s (%s).', state.remoteHost, state.host);
    ws.emit('tcp close');
    ws.disconnect();
  });

  ws.on('tcp data', function(data) {
    if (typeof data !== 'string')
      return;
    socket.write(new Buffer(data, 'hex'));
  });

  ws.on('disconnect', function() {
    socket.destroy();
  });
};

WSProxy.prototype.log = function log() {
  process.stdout.write('wsproxy: ');
  console.log.apply(console, arguments);
};

WSProxy.prototype.attach = function attach(server) {
  this.io.attach(server);
};

function SocketState(server, socket) {
  this.pow = server.pow;
  this.target = server.target;
  this.snonce = util.nonce(true);
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
  this.remoteHost = IP.hostname(host, port);
  return this.socket;
};

module.exports = WSProxy;
