'use strict';

const FullNode = require('bcoin/lib/node/fullnode');

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

const node = new FullNode({
  network: 'testnet',
  db: 'memory',
  workers: true
});

node.use(MyPlugin);

(async () => {
  let plugin = node.require('my-plugin');

  await node.open();

  await node.connect();

  plugin.sayPeers();

  node.on('connect', (entry, block) => {
    console.log('%s (%d) added to chain.', entry.rhash(), entry.height);
  });

  node.on('tx', (tx) => {
    console.log('%s added to mempool.', tx.txid());
  });

  node.startSync();
})();
