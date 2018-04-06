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

const wallet = new client.WalletClient({
  port: network.walletPort,
  apiKey: 'foo'
});

async function fundWallet(wdb, addr) {
  // Coinbase
  const mtx = new bcoin.MTX();
  mtx.addOutpoint(new bcoin.Outpoint());
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);
  mtx.addOutput(addr, 50460);

  const tx = mtx.toTX();

  wallet.once('balance', (balance) => {
    console.log('New Balance:');
    console.log(balance);
  });

  wallet.once('address', (receive) => {
    console.log('New Receiving Address:');
    console.log(receive);
  });

  wallet.once('tx', (details) => {
    console.log('New Wallet TX:');
    console.log(details);
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

  const tx = await wallet.send('test', options);

  return tx.hash;
}

async function callNodeApi() {
  const info = await wallet.client.getInfo();

  console.log('Server Info:');
  console.log(info);

  const json = await wallet.client.rpc.execute('getblocktemplate', []);

  console.log('Block Template (RPC):');
  console.log(json);
}

(async () => {
  const wdb = node.require('walletdb').wdb;

  await node.open();

  const w = await wallet.createWallet('test');

  console.log('Wallet:');
  console.log(w);

  // Fund default account.
  const receive = await wallet.createAddress('test', 'default');
  await fundWallet(wdb, receive.address);

  const balance = await wallet.getBalance('test', 'default');

  console.log('Balance:');
  console.log(balance);

  const acct = await wallet.createAccount('test', 'foo');

  console.log('Account:');
  console.log(acct);

  // Send to our new account.
  const hash = await sendTX(acct.receiveAddress, 10000);

  console.log('Sent TX:');
  console.log(hash);

  const tx = await wallet.getTX(hash);

  console.log('Sent TX details:');
  console.log(tx);

  await callNodeApi();
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
