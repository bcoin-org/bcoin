/*!
 * proxysocket.js - wsproxy socket for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const bsock = require('bsock');
const hash256 = require('bcrypto/lib/hash256');
const BufferWriter = require('bbuf/lib/writer');

function ProxySocket(uri) {
  if (!(this instanceof ProxySocket))
    return new ProxySocket(uri);

  EventEmitter.call(this);

  this.info = null;

  this.socket = bsock.connect(uri);
  this.sendBuffer = [];
  this.recvBuffer = [];
  this.paused = false;
  this.snonce = null;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this.remoteAddress = null;
  this.remotePort = 0;

  this.closed = false;

  this.init();
}

Object.setPrototypeOf(ProxySocket.prototype, EventEmitter.prototype);

ProxySocket.prototype.init = function init() {
  this.socket.bind('info', (info) => {
    if (this.closed)
      return;

    this.info = info;

    if (info.pow) {
      this.snonce = Buffer.from(info.snonce, 'hex');
      this.target = Buffer.from(info.target, 'hex');
    }

    this.emit('info', info);
  });

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

  this.socket.bind('disconnect', () => {
    if (this.closed)
      return;
    this.closed = true;
    this.emit('close');
  });
};

ProxySocket.prototype.connect = function connect(port, host) {
  this.remoteAddress = host;
  this.remotePort = port;

  if (this.closed) {
    this.sendBuffer.length = 0;
    return;
  }

  if (!this.info) {
    this.once('info', connect.bind(this, port, host));
    return;
  }

  let nonce = 0;

  if (this.info.pow) {
    const bw = new BufferWriter();

    bw.writeU32(nonce);
    bw.writeBytes(this.snonce);
    bw.writeU32(port);
    bw.writeString(host, 'ascii');

    const pow = bw.render();

    console.log(
      'Solving proof of work to create socket (%d, %s) -- please wait.',
      port, host);

    do {
      nonce++;
      assert(nonce <= 0xffffffff, 'Could not create socket.');
      pow.writeUInt32LE(nonce, 0, true);
    } while (hash256.digest(pow).compare(this.target) > 0);

    console.log('Solved proof of work: %d', nonce);
  }

  this.socket.fire('tcp connect', port, host, nonce);

  for (const chunk of this.sendBuffer)
    this.write(chunk);

  this.sendBuffer.length = 0;
};

ProxySocket.prototype.setKeepAlive = function setKeepAlive(enable, delay) {
  this.socket.fire('tcp keep alive', enable, delay);
};

ProxySocket.prototype.setNoDelay = function setNoDelay(enable) {
  this.socket.fire('tcp no delay', enable);
};

ProxySocket.prototype.setTimeout = function setTimeout(timeout, callback) {
  this.socket.fire('tcp set timeout', timeout);
  if (callback)
    this.on('timeout', callback);
};

ProxySocket.prototype.write = function write(data, callback) {
  if (!this.info) {
    this.sendBuffer.push(data);

    if (callback)
      callback();

    return true;
  }

  this.bytesWritten += data.length;

  this.socket.fire('tcp data', data.toString('hex'));

  if (callback)
    callback();

  return true;
};

ProxySocket.prototype.pause = function pause() {
  this.paused = true;
};

ProxySocket.prototype.resume = function resume() {
  const recv = this.recvBuffer;

  this.paused = false;
  this.recvBuffer = [];

  for (const data of recv) {
    this.bytesRead += data.length;
    this.emit('data', data);
  }
};

ProxySocket.prototype.destroy = function destroy() {
  if (this.closed)
    return;
  this.closed = true;
  this.socket.destroy();
};

ProxySocket.connect = function connect(uri, port, host) {
  const socket = new ProxySocket(uri);
  socket.connect(port, host);
  return socket;
};

module.exports = ProxySocket;
