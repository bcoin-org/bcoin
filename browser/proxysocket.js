'use strict';

var bcoin = require('../lib/bcoin/env');
var utils = bcoin.utils;
var BufferWriter = require('../lib/bcoin/utils/writer');
var assert = utils.assert;
var EventEmitter = require('events').EventEmitter;
var IOClient = require('socket.io-client');

function ProxySocket(uri) {
  var self = this;

  if (!(this instanceof ProxySocket))
    return new ProxySocket(uri);

  EventEmitter.call(this);

  this.info = null;

  this.socket = new IOClient(uri, { reconnection: false });
  this.sendBuffer = [];
  this.snonce = null;

  this.closed = false;

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

  this.socket.on('tcp connect', function() {
    if (self.closed)
      return;
    self.emit('connect');
  });

  this.socket.on('tcp data', function(data) {
    self.emit('data', new Buffer(data, 'hex'));
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

  this.socket.on('close', function() {
    if (self.closed)
      return;
    self.closed = true;
    self.emit('close');
  });
}

utils.inherits(ProxySocket, EventEmitter);

ProxySocket.prototype.connect = function connect(port, host) {
  var nonce = 0;
  var i, pow;

  if (this.closed) {
    this.sendBuffer.length = 0;
    return;
  }

  if (!this.info)
    return this.once('info', connect.bind(this, port, host));

  if (this.info.pow) {
    utils.log(
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
    } while (utils.cmp(utils.dsha256(pow), this.target) > 0);

    utils.log('Solved proof of work: %d', nonce);
  }

  this.socket.emit('tcp connect', port, host, nonce);

  for (i = 0; i < this.sendBuffer.length; i++)
    this.write(this.sendBuffer[i]);

  this.sendBuffer.length = 0;
};

ProxySocket.prototype.write = function write(data) {
  if (!this.info) {
    this.sendBuffer.push(data);
    return true;
  }
  this.socket.emit('tcp data', data.toString('hex'));
  return true;
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
