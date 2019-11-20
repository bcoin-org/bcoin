/* eslint-env mocha */

'use strict';

const assert = require('bsert');
const SIO = require('./vendor/socket.io');
const SIOC = require('./vendor/socket.io-client');
const http = require('http');
const bsock = require('../');

function timeout(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function emit(socket, event) {
  return new Promise((resolve, reject) => {
    socket.emit(event, (err, res) => {
      if (err)
        reject(err);
      else
        resolve(res);
    });
  });
}

describe('Socket', () => {
  describe('socket.io client -> bsock server', () => {
    const io = bsock.createServer();
    const server = http.createServer();

    let socket = null;
    let barData = null;

    it('should setup server', (cb) => {
      io.attach(server);

      io.on('socket', (socket) => {
        socket.on('error', () => {});

        socket.hook('foo', async () => {
          return Buffer.from('test', 'ascii');
        });

        socket.hook('err', async () => {
          throw new Error('Bad call.');
        });

        socket.bind('bar', (data) => {
          assert(!barData);
          barData = data;
        });
      });

      server.listen(8000, cb);
    });

    it('should setup socket', () => {
      socket = new SIOC('ws://127.0.0.1:8000', {
        transports: ['websocket'],
        forceNew: true
      });
    });

    it('should call hook', async () => {
      const data = await emit(socket, 'foo');

      assert(Buffer.isBuffer(data));
      assert.bufferEqual(data, 'test', 'ascii');
    });

    it('should call error hook', async () => {
      await assert.rejects(emit(socket, 'err'), {
        message: 'Bad call.'
      });
    });

    it('should fire event', async () => {
      socket.emit('bar', Buffer.from('baz'));

      await timeout(100);

      assert(Buffer.isBuffer(barData));
      assert.bufferEqual(barData, 'baz', 'ascii');
    });

    it('should close', (cb) => {
      socket.destroy();
      server.close(cb);
    });
  });

  describe('bsock client -> socket.io server', () => {
    const io = new SIO({
      transports: ['websocket'],
      serveClient: false
    });

    const server = http.createServer();

    let socket = null;
    let barData = null;

    it('should setup server', (cb) => {
      io.attach(server);

      io.on('connection', (socket) => {
        socket.on('foo', async (cb) => {
          cb(null, Buffer.from('test', 'ascii'));
        });

        socket.on('err', (cb) => {
          cb({ message: 'Bad call.' });
        });

        socket.on('bar', (data) => {
          assert(!barData);
          barData = data;
        });
      });

      server.listen(8000, cb);
    });

    it('should setup socket', () => {
      socket = bsock.connect(8000);
      socket.on('error', () => {});
    });

    it('should call hook', async () => {
      const data = await socket.call('foo');

      assert(Buffer.isBuffer(data));
      assert.bufferEqual(data, 'test', 'ascii');
    });

    it('should call error hook', async () => {
      await assert.rejects(socket.call('err'), {
        message: 'Bad call.'
      });
    });

    it('should fire event', async () => {
      socket.fire('bar', Buffer.from('baz'));

      await timeout(100);

      assert(Buffer.isBuffer(barData));
      assert.bufferEqual(barData, 'baz', 'ascii');
    });

    it('should close', (cb) => {
      socket.destroy();
      server.close(cb);
    });
  });

  describe('bsock client -> bsock server', () => {
    const io = bsock.createServer();
    const server = http.createServer();

    let socket = null;
    let barData = null;

    it('should setup server', (cb) => {
      io.attach(server);

      io.on('socket', (socket) => {
        socket.on('error', () => {});

        socket.hook('echo', async (json) => {
          return json;
        });

        socket.hook('foo', async () => {
          return Buffer.from('test', 'ascii');
        });

        socket.hook('err', async () => {
          throw new Error('Bad call.');
        });

        socket.bind('bar', (data) => {
          assert(!barData);
          barData = data;
        });

        socket.bind('join', (name) => {
          io.join(socket, name);
          io.to(name, 'test', 'testing');
          io.leave(socket, name);
          io.to(name, 'test', 'testing again');
        });
      });

      server.listen(8000, cb);
    });

    it('should setup socket', () => {
      socket = bsock.connect(8000);
      socket.on('error', () => {});
    });

    it('should call hook', async () => {
      const data = await socket.call('foo');

      assert(Buffer.isBuffer(data));
      assert.bufferEqual(data, 'test', 'ascii');
    });

    it('should call error hook', async () => {
      await assert.rejects(socket.call('err'), {
        message: 'Bad call.'
      });
    });

    it('should fire event', async () => {
      socket.fire('bar', Buffer.from('baz'));

      await timeout(100);

      assert(Buffer.isBuffer(barData));
      assert.bufferEqual(barData, 'baz', 'ascii');
    });

    it('should receive channel event', async () => {
      const data = [];

      socket.bind('test', (str) => {
        data.push(str);
      });

      socket.fire('join', 'test-channel');

      await timeout(100);

      assert.strictEqual(data.length, 1);
      assert.strictEqual(data[0], 'testing');
    });

    it('should send complex data', async () => {
      const obj = {
        foo: {
          a: 1,
          b: 'z',
          c: Buffer.from('foo')
        },
        bar: {
          d: 100,
          e: 'bar'
        }
      };

      const json = await socket.call('echo', obj);

      assert.deepStrictEqual(json, obj);
    });

    it('should close', (cb) => {
      socket.destroy();
      server.close(cb);
    });
  });
});
