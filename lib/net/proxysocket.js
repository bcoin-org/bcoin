/*!
 * proxysocket.js - wsproxy socket for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const IOClient = require('socket.io-client');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const BufferWriter = require('../utils/writer');

function ProxySocket(uri) {
  if (!(this instanceof ProxySocket))
    return new ProxySocket(uri);

  EventEmitter.call(this);

  this.info = null;

  this.socket = new IOClient(uri, { reconnection: false });
  this.sendBuffer = [];
  this.recvBuffer = [];
  this.paused = false;
  this.snonce = null;
  this.bytesWritten = 0;
  this.bytesRead = 0;
  this.remoteAddress = null;
  this.remotePort = 0;

  this.closed = false;

  this._init();
}

util.inherits(ProxySocket, EventEmitter);

ProxySocket.prototype._init = function _init() {
  this.socket.on('info', (info) => {
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

  this.socket.on('tcp connect', (addr, port) => {
    if (this.closed)
      return;
    this.remoteAddress = addr;
    this.remotePort = port;
    this.emit('connect');
  });

  this.socket.on('tcp data', (data) => {
    data = Buffer.from(data, 'hex');
    if (this.paused) {
      this.recvBuffer.push(data);
      return;
    }
    this.bytesRead += data.length;
    this.emit('data', data);
  });

  this.socket.on('tcp close', (data) => {
    if (this.closed)
      return;
    this.closed = true;
    this.emit('close');
  });

  this.socket.on('tcp error', (e) => {
    let err = new Error(e.message);
    err.code = e.code;
    this.emit('error', err);
  });

  this.socket.on('tcp timeout', () => {
    this.emit('timeout');
  });

  this.socket.on('disconnect', () => {
    if (this.closed)
      return;
    this.closed = true;
    this.emit('close');
  });
};

ProxySocket.prototype.connect = function connect(port, host) {
  let nonce = 0;

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

  if (this.info.pow) {
    let pow = new BufferWriter();

    pow.writeU32(nonce);
    pow.writeBytes(this.snonce);
    pow.writeU32(port);
    pow.writeString(host, 'ascii');
    pow = pow.render();

    util.log(
      'Solving proof of work to create socket (%d, %s) -- please wait.',
      port, host);

    do {
      nonce++;
      assert(nonce <= 0xffffffff, 'Could not create socket.');
      pow.writeUInt32LE(nonce, 0, true);
    } while (digest.hash256(pow).compare(this.target) > 0);

    util.log('Solved proof of work: %d', nonce);
  }

  this.socket.emit('tcp connect', port, host, nonce);

  for (let chunk of this.sendBuffer)
    this.write(chunk);

  this.sendBuffer.length = 0;
};

ProxySocket.prototype.setKeepAlive = function setKeepAlive(enable, delay) {
  this.socket.emit('tcp keep alive', enable, delay);
};

ProxySocket.prototype.setNoDelay = function setNoDelay(enable) {
  this.socket.emit('tcp no delay', enable);
};

ProxySocket.prototype.setTimeout = function setTimeout(timeout, callback) {
  this.socket.emit('tcp set timeout', timeout);
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

  this.socket.emit('tcp data', data.toString('hex'));

  if (callback)
    callback();

  return true;
};

ProxySocket.prototype.pause = function pause() {
  this.paused = true;
};

ProxySocket.prototype.resume = function resume() {
  let recv = this.recvBuffer;

  this.paused = false;
  this.recvBuffer = [];

  for (let data of recv) {
    this.bytesRead += data.length;
    this.emit('data', data);
  }
};

ProxySocket.prototype.destroy = function destroy() {
  if (this.closed)
    return;
  this.closed = true;
  this.socket.disconnect();
};

ProxySocket.connect = function connect(uri, port, host) {
  let socket = new ProxySocket(uri);
  socket.connect(port, host);
  return socket;
};

module.exports = ProxySocket;
