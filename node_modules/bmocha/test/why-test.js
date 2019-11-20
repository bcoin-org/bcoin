'use strict';

const net = require('net');

// Based on:
// https://github.com/mafintosh/why-is-node-running

function createServer() {
  const server = net.createServer();
  setInterval(() => {}, 1000);
  server.listen(0);
}

describe('Why', () => {
  it('should not end', () => {
    createServer();
    createServer();
  });
});
