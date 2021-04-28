'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const Packet = require('./packet');
const WebSocket = require('./backend');
const Socket = require('./socket');

class Server extends EventEmitter {
  constructor(options = {}) {
    super();

    assert(!options.protocols || Array.isArray(options.protocols));

    this.protocols = options.protocols || undefined;
    this.sockets = new Set();
    this.channels = new Map();
    this.mounts = [];
    this.mounted = false;
  }

  handleSocket(socket) {
    this.add(socket);

    socket.on('close', () => {
      this.remove(socket);
    });

    this.emit('socket', socket);

    for (const server of this.mounts)
      server.emit('socket', socket);
  }

  mount(server) {
    assert(!server.mounted);
    server.mounted = true;
    server.sockets = this.sockets;
    server.channels = this.channels;
    this.mounts.push(server);
  }

  async open() {
    ;
  }

  async close() {
    if (this.mounted)
      return;

    for (const socket of this.sockets)
      socket.destroy();
  }

  attach(server) {
    const onUpgrade = (req, socket, body) => {
      if (!socket.remoteAddress) {
        socket.destroy();
        return;
      }

      if (!WebSocket.isWebSocket(req)) {
        socket.destroy();
        return;
      }

      const ws = new WebSocket(req, socket, body, this.protocols);
      const sock = Socket.accept(this, req, socket, ws);

      this.handleSocket(sock);
    };

    server.on('upgrade', (req, socket, body) => {
      try {
        onUpgrade(req, socket, body);
      } catch (e) {
        this.emit('error', e);
      }
    });

    return this;
  }

  add(socket) {
    this.sockets.add(socket);
  }

  remove(socket) {
    for (const name of socket.channels)
      this.leave(socket, name);

    assert(this.sockets.delete(socket));
  }

  join(socket, name) {
    if (socket.channels.has(name))
      return false;

    if (!this.channels.has(name))
      this.channels.set(name, new Set());

    const sockets = this.channels.get(name);

    sockets.add(socket);
    socket.channels.add(name);

    return true;
  }

  leave(socket, name) {
    if (!socket.channels.has(name))
      return false;

    const sockets = this.channels.get(name);

    assert(sockets);
    assert(sockets.delete(socket));

    if (sockets.size === 0)
      this.channels.delete(name);

    socket.channels.delete(name);

    return true;
  }

  channel(name) {
    const sockets = this.channels.get(name);

    if (!sockets)
      return null;

    assert(sockets.size > 0);

    return sockets;
  }

  event(args) {
    assert(args.length > 0, 'Event must be present.');
    assert(typeof args[0] === 'string', 'Event must be a string.');
    const packet = new Packet();
    packet.type = Packet.types.EVENT;
    packet.setData(args);
    return packet;
  }

  to(name, ...args) {
    const sockets = this.channels.get(name);

    if (!sockets)
      return;

    assert(sockets.size > 0);

    // Pre-serialize for speed.
    const packet = this.event(args);

    for (const socket of sockets)
      socket.sendPacket(packet);
  }

  all(...args) {
    // Pre-serialize for speed.
    const packet = this.event(args);

    for (const socket of this.sockets)
      socket.sendPacket(packet);
  }

  static attach(parent, options) {
    const server = new this(options);
    return server.attach(parent);
  }

  static createServer(options) {
    return new this(options);
  }
}

module.exports = Server;
