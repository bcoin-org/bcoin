/*!
 * proxysocket.js - wsproxy socket for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const bsock = require('bsock');

class ProxySocket extends EventEmitter {
  constructor(uri) {
    super();

    this.socket = bsock.socket();
    this.socket.reconnection = false;
    this.socket.connect(uri);

    this.sendBuffer = [];
    this.recvBuffer = [];
    this.paused = false;
    this.bytesWritten = 0;
    this.bytesRead = 0;
    this.remoteAddress = null;
    this.remotePort = 0;

    this.closed = false;

    this.init();
  }

  init() {
    this.socket.on('error', (err) => {
      console.error(err);
    });

    this.socket.bind('tcp connect', (addr, port) => {
      if (this.closed)
        return;
      this.remoteAddress = addr;
      this.remotePort = port;
      this.emit('connect');
    });

    this.socket.bind('tcp data', (data) => {
      data = Buffer.from(data, 'hex');
      if (this.paused) {
        this.recvBuffer.push(data);
        return;
      }
      this.bytesRead += data.length;
      this.emit('data', data);
    });

    this.socket.bind('tcp close', (data) => {
      if (this.closed)
        return;
      this.closed = true;
      this.emit('close');
    });

    this.socket.bind('tcp error', (e) => {
      const err = new Error(e.message);
      err.code = e.code;
      this.emit('error', err);
    });

    this.socket.bind('tcp timeout', () => {
      this.emit('timeout');
    });

    this.socket.on('disconnect', () => {
      if (this.closed)
        return;
      this.closed = true;
      this.emit('close');
    });
  }

  connect(port, host) {
    this.remoteAddress = host;
    this.remotePort = port;

    if (this.closed) {
      this.sendBuffer.length = 0;
      return;
    }

    this.socket.fire('tcp connect', port, host);

    for (const chunk of this.sendBuffer)
      this.write(chunk);

    this.sendBuffer.length = 0;
  }

  setKeepAlive(enable, delay) {
    this.socket.fire('tcp keep alive', enable, delay);
  }

  setNoDelay(enable) {
    this.socket.fire('tcp no delay', enable);
  }

  setTimeout(timeout, callback) {
    this.socket.fire('tcp set timeout', timeout);
    if (callback)
      this.on('timeout', callback);
  }

  write(data, callback) {
    this.bytesWritten += data.length;

    this.socket.fire('tcp data', data.toString('hex'));

    if (callback)
      callback();

    return true;
  }

  pause() {
    this.paused = true;
  }

  resume() {
    const recv = this.recvBuffer;

    this.paused = false;
    this.recvBuffer = [];

    for (const data of recv) {
      this.bytesRead += data.length;
      this.emit('data', data);
    }
  }

  destroy() {
    if (this.closed)
      return;
    this.closed = true;
    this.socket.destroy();
  }

  static connect(uri, port, host) {
    const socket = new this(uri);
    socket.connect(port, host);
    return socket;
  }
}

module.exports = ProxySocket;
