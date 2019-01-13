'use strict';

const bcoin = require('../..');

function MyPlugin(node) {
  this.node = node;
}

MyPlugin.id = 'my-plugin';

MyPlugin.init = function init(node) {
  return new MyPlugin(node);
};

MyPlugin.prototype.open = function open() {
  console.log('Opened my plugin.');
  return Promise.resolve();
};

MyPlugin.prototype.close = function close() {
  console.log('Closed my plugin.');
  return Promise.resolve();
};

MyPlugin.prototype.sayPeers = function sayPeers() {
  console.log('Number of peers: %d', this.node.pool.peers.size());
};

const node = new bcoin.FullNode({
  memory: true,
  network: 'testnet',
  workers: true
});

node.use(MyPlugin);

(async () => {
  const plugin = node.require('my-plugin');

  await node.open();

  await node.connect();

  plugin.sayPeers();

  await node.close();
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
