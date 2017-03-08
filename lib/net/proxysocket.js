'use strict';

var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var BufferWriter = require('../utils/writer');
var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var IOClient = require('socket.io-client');

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
  var self = this;

  this.socket.on('info', function(info) {
    if (self.closed)
      return;

    self.info = info;

    if (info.pow) {
      self.snonce = new Buffer(info.snonce, 'hex');
      self.target = new Buffer(info.target, 'hex');
    }

    self.emit('info', info);
  });

  this.socket.on('error', function(err) {
    console.error(err);
  });

  this.socket.on('tcp connect', function(addr, port) {
    if (self.closed)
      return;
    self.remoteAddress = addr;
    self.remotePort = port;
    self.emit('connect');
  });

  this.socket.on('tcp data', function(data) {
    data = new Buffer(data, 'hex');
    if (self.paused) {
      self.recvBuffer.push(data);
      return;
    }
    self.bytesRead += data.length;
    self.emit('data', data);
  });

  this.socket.on('tcp close', function(data) {
    if (self.closed)
      return;
    self.closed = true;
    self.emit('close');
  });

  this.socket.on('tcp error', function(e) {
    var err = new Error(e.message);
    err.code = e.code;
    self.emit('error', err);
  });

  this.socket.on('tcp timeout', function() {
    self.emit('timeout');
  });

  this.socket.on('disconnect', function() {
    if (self.closed)
      return;
    self.closed = true;
    self.emit('close');
  });
};

ProxySocket.prototype.connect = function connect(port, host) {
  var nonce = 0;
  var i, pow;

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
    util.log(
      'Solving proof of work to create socket (%d, %s) -- please wait.',
      port, host);

    pow = new BufferWriter();
    pow.writeU32(nonce);
    pow.writeBytes(this.snonce);
    pow.writeU32(port);
    pow.writeString(host, 'ascii');
    pow = pow.render();

    do {
      nonce++;
      assert(nonce <= 0xffffffff, 'Could not create socket.');
      pow.writeUInt32LE(nonce, 0, true);
    } while (util.cmp(crypto.hash256(pow), this.target) > 0);

    util.log('Solved proof of work: %d', nonce);
  }

  this.socket.emit('tcp connect', port, host, nonce);

  for (i = 0; i < this.sendBuffer.length; i++)
    this.write(this.sendBuffer[i]);

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
  var recv = this.recvBuffer;
  var i, data;

  this.paused = false;
  this.recvBuffer = [];

  for (i = 0; i < recv.length; i++) {
    data = recv[i];
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
  var socket = new ProxySocket(uri);
  socket.connect(port, host);
  return socket;
};

module.exports = ProxySocket;
