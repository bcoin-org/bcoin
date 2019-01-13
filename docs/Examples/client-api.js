'use strict';

const bcoin = require('../..');
const client = require('bclient');
const plugin = bcoin.wallet.plugin;
const network = bcoin.Network.get('regtest');

const node = new bcoin.FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  db: 'memory'
});

node.use(plugin);

const walletClient = new client.WalletClient({
  port: network.walletPort,
  apiKey: 'foo'
});

const nodeClient = new client.NodeClient({
  port: network.rpcPort,
  apiKey: 'foo'
});

async function fundWallet(wdb, addr) {
  // Coinbase
  const mtx = new bcoin.MTX();
  mtx.addOutpoint(new bcoin.Outpoint(bcoin.consensus.ZERO_HASH, 0));
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);

  const tx = mtx.toTX();

  walletClient.bind('balance', (walletID, balance) => {
    console.log('New Balance:');
    console.log(walletID, balance);
  });

  walletClient.bind('address', (walletID, receive) => {
    console.log('New Receiving Address:');
    console.log(walletID, receive);
  });

  walletClient.bind('tx', (walletID, details) => {
    console.log('New Wallet TX:');
    console.log(walletID, details);
  });

  await wdb.addTX(tx);
  await new Promise(r => setTimeout(r, 300));
}

async function sendTX(addr, value) {
  const options = {
    rate: 10000,
    outputs: [{
      value: value,
      address: addr
    }]
  };

  const tx = await walletClient.send('test', options);

  return tx.hash;
}

async function callNodeApi() {
  const info = await nodeClient.getInfo();

  console.log('Server Info:');
  console.log(info);

  const json = await nodeClient.execute('getblocktemplate', []);

  console.log('Block Template (RPC):');
  console.log(json);
}

(async () => {
  const wdb = node.require('walletdb').wdb;

  await node.open();

  const testWallet = await walletClient.createWallet('test');

  console.log('Wallet:');
  console.log(testWallet);

  // open socket to listen for events
  await walletClient.open();

  // subscribe to events from all wallets
  walletClient.all()

  // Fund default account.
  const receive = await walletClient.createAddress('test', 'default');
  await fundWallet(wdb, receive.address);

  const balance = await walletClient.getBalance('test', 'default');

  console.log('Balance:');
  console.log(balance);

  const acct = await walletClient.createAccount('test', 'foo');

  console.log('Account:');
  console.log(acct);

  // Send to our new account.
  const hash = await sendTX(acct.receiveAddress, 10000);

  console.log('Sent TX:');
  console.log(hash);

  const tx = await walletClient.getTX('test', hash);

  console.log('Sent TX details:');
  console.log(tx);

  await callNodeApi();
  process.exit(0);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
