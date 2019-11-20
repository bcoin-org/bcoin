/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const http = require('http');
const request = require('../');

describe('Request', function() {
  let server = null;

  it('should setup http server', async () => {
    server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/foo') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.write('hello world\n');
        res.end();
        return;
      }

      if (req.method === 'GET' && req.url === '/foo.json') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.write('{"hello":"world"}\n');
        res.end();
        return;
      }

      if (req.method === 'POST' && req.url === '/echo') {
        const type = req.headers['content-type'] || 'text/plain; charset=utf-8';
        res.statusCode = 200;
        res.setHeader('Content-Type', type);
        req.pipe(res);
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(9080, '127.0.0.1', () => {
        server.removeListener('error', reject);
        resolve();
      });
    });
  });

  it('should do GET request', async () => {
    const res = await request({
      method: 'GET',
      url: 'http://127.0.0.1:9080/foo',
      expect: 'txt'
    });

    assert.strictEqual(res.text(), 'hello world\n');
  });

  it('should do GET request (json)', async () => {
    const res = await request({
      method: 'GET',
      url: 'http://127.0.0.1:9080/foo.json',
      expect: 'json'
    });

    assert.deepStrictEqual(res.json(), { hello: 'world' });
  });

  it('should do POST request (json)', async () => {
    const res = await request({
      method: 'POST',
      url: 'http://127.0.0.1:9080/echo',
      expect: 'json',
      json: {
        foo: 1
      }
    });

    assert.deepStrictEqual(res.json(), { foo: 1 });
  });

  it('should close server', async () => {
    return new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  });
});
