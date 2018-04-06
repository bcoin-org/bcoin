'use strict';

const assert = require('assert');
const net = require('net');
const EventEmitter = require('events');
const bsock = require('bsock');
const IP = require('binet');

class WSProxy extends EventEmitter {
  constructor(options) {
    super();

    if (!options)
      options = {};

    this.options = options;
    this.ports = new Set();
    this.io = bsock.server();
    this.sockets = new WeakMap();

    if (options.ports) {
      for (const port of options.ports)
        this.ports.add(port);
    }

    this.init();
  }

  init() {
    this.io.on('error', (err) => {
      this.emit('error', err);
    });

    this.io.on('socket', (ws) => {
      this.handleSocket(ws);
    });
  }

  handleSocket(ws) {
    const state = new SocketState(this, ws);

    // Use a weak map to avoid
    // mutating the websocket object.
    this.sockets.set(ws, state);

    ws.on('error', (err) => {
      this.emit('error', err);
    });

    ws.bind('tcp connect', (port, host) => {
      this.handleConnect(ws, port, host);
    });
  }

  handleConnect(ws, port, host) {
    const state = this.sockets.get(ws);
    assert(state);

    if (state.socket) {
      this.log('Client is trying to reconnect (%s).', state.host);
      return;
    }

    if ((port & 0xffff) !== port
        || typeof host !== 'string'
        || host.length === 0) {
      this.log('Client gave bad arguments (%s).', state.host);
      ws.fire('tcp close');
      ws.destroy();
      return;
    }

    let raw, addr;
    try {
      raw = IP.toBuffer(host);
      addr = IP.toString(raw);
    } catch (e) {
      this.log('Client gave a bad host: %s (%s).', host, state.host);
      ws.fire('tcp error', {
        message: 'EHOSTUNREACH',
        code: 'EHOSTUNREACH'
      });
      ws.destroy();
      return;
    }

    if (!IP.isRoutable(raw) || IP.isOnion(raw)) {
      this.log(
        'Client is trying to connect to a bad ip: %s (%s).',
        addr, state.host);
      ws.fire('tcp error', {
        message: 'ENETUNREACH',
        code: 'ENETUNREACH'
      });
      ws.destroy();
      return;
    }

    if (!this.ports.has(port)) {
      this.log('Client is connecting to non-whitelist port (%s).', state.host);
      ws.fire('tcp error', {
        message: 'ENETUNREACH',
        code: 'ENETUNREACH'
      });
      ws.destroy();
      return;
    }

    let socket;
    try {
      socket = state.connect(port, addr);
      this.log('Connecting to %s (%s).', state.remoteHost, state.host);
    } catch (e) {
      this.log(e.message);
      this.log('Closing %s (%s).', state.remoteHost, state.host);
      ws.fire('tcp error', {
        message: 'ENETUNREACH',
        code: 'ENETUNREACH'
      });
      ws.destroy();
      return;
    }

    socket.on('connect', () => {
      ws.fire('tcp connect', socket.remoteAddress, socket.remotePort);
    });

    socket.on('data', (data) => {
      ws.fire('tcp data', data.toString('hex'));
    });

    socket.on('error', (err) => {
      ws.fire('tcp error', {
        message: err.message,
        code: err.code || null
      });
    });

    socket.on('timeout', () => {
      ws.fire('tcp timeout');
    });

    socket.on('close', () => {
      this.log('Closing %s (%s).', state.remoteHost, state.host);
      ws.fire('tcp close');
      ws.destroy();
    });

    ws.bind('tcp data', (data) => {
      if (typeof data !== 'string')
        return;
      socket.write(Buffer.from(data, 'hex'));
    });

    ws.bind('tcp keep alive', (enable, delay) => {
      socket.setKeepAlive(enable, delay);
    });

    ws.bind('tcp no delay', (enable) => {
      socket.setNoDelay(enable);
    });

    ws.bind('tcp set timeout', (timeout) => {
      socket.setTimeout(timeout);
    });

    ws.bind('tcp pause', () => {
      socket.pause();
    });

    ws.bind('tcp resume', () => {
      socket.resume();
    });

    ws.on('disconnect', () => {
      socket.destroy();
    });
  }

  log(...args) {
    process.stdout.write('wsproxy: ');
    console.log(...args);
  }

  attach(server) {
    this.io.attach(server);
  }
}

class SocketState {
  constructor(server, socket) {
    this.socket = null;
    this.host = socket.host;
    this.remoteHost = null;
  }

  connect(port, host) {
    this.socket = net.connect(port, host);
    this.remoteHost = IP.toHostname(host, port);
    return this.socket;
  }
}

module.exports = WSProxy;
