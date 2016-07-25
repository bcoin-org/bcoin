'use strict';

var http = require('http');
var net = require('net');
var IOServer = require('socket.io');
var utils = require('../lib/bcoin/utils');
var IP = require('../lib/bcoin/ip');
var network = require('../lib/bcoin/protocol/network');
var BufferWriter = require('../lib/bcoin/writer');
var ports = [];
var i, type;

for (i = 0; i < network.types.length; i++) {
  type = network.types[i];
  ports.push(network[type].port);
}

module.exports = function wsproxy(options) {
  var target, io;

  if (!options)
    options = {};

  target = new Buffer(
    '0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'hex');

  io = new IOServer();

  io.on('error', function(err) {
    utils.error(err.stack + '');
  });

  io.on('connection', function(ws) {
    var snonce = utils.nonce().toArrayLike(Buffer, 'be', 8);
    var socket, pow;

    ws.emit('info', {
      pow: !!options.pow,
      snonce: snonce.toString('hex'),
      target: target.toString('hex')
    });

    ws.on('error', function(err) {
      utils.error(err.stack + '');
    });

    ws.on('tcp connect', function(port, host, nonce) {
      if (socket)
        return;

      if (!utils.isNumber(port)
          || typeof host !== 'string') {
        utils.error('Client gave bad arguments.');
        ws.emit('tcp close');
        ws.disconnect();
        return;
      }

      if (options.pow) {
        if (!utils.isNumber(nonce)) {
          utils.error('Client did not solve proof of work.');
          ws.emit('tcp close');
          ws.disconnect();
          return;
        }

        pow = new BufferWriter();
        pow.writeU32(nonce);
        pow.writeBytes(snonce);
        pow.writeU32(port);
        pow.writeString(host, 'ascii');
        pow = pow.render();

        if (utils.cmp(utils.dsha256(pow), target) >= 0) {
          utils.error('Client did not solve proof of work.');
          ws.emit('tcp close');
          ws.disconnect();
          return;
        }
      }

      if (!/^[a-zA-Z0-9\.:\-]+$/.test(host)) {
        utils.error('Client gave a bad host.');
        ws.emit('tcp close');
        ws.disconnect();
        return;
      }

      if (IP.isPrivate(host)) {
        utils.error('Client is trying to connect to a private ip.');
        ws.emit('tcp close');
        ws.disconnect();
        return;
      }

      if (ports.indexOf(port) === -1) {
        utils.error('Client is trying to connect to a non-bitcoin port.');
        ws.emit('tcp close');
        ws.disconnect();
        return;
      }

      try {
        socket = net.connect(port, host);
        utils.error('Connecting to %s:%d.', host, port);
      } catch (e) {
        utils.error('Closing %s:%d.', host, port);
        ws.emit('tcp close');
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
        utils.error('Closing %s:%d.', host, port);
        ws.emit('tcp close');
        ws.disconnect();
      });

      ws.on('tcp data', function(data) {
        socket.write(new Buffer(data, 'hex'));
      });

      ws.on('disconnect', function() {
        socket.destroy();
      });

      ws.on('close', function() {
        socket.destroy();
      });
    });
  });

  return io;
};
