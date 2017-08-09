'use strict';

const bcoin = require('../..');
const encoding = bcoin.encoding;
const co = bcoin.co;
const Outpoint = bcoin.outpoint;
const MTX = bcoin.mtx;
const HTTP = bcoin.http;
const FullNode = bcoin.fullnode;
const plugin = bcoin.wallet.plugin;

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  db: 'memory'
});

node.use(plugin);

const wallet = new HTTP.Wallet({
  network: 'regtest',
  apiKey: 'foo'
});

async function fundWallet(wdb, addr) {
  // Coinbase
  const mtx = new MTX();
  mtx.addOutpoint(new Outpoint(encoding.NULL_HASH, 0));
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
  await co.timeout(300);
}

async function sendTX(addr, value) {
  const options = {
    rate: 10000,
    outputs: [{
      value: value,
      address: addr
    }]
  };

  const tx = await wallet.send(options);

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
  const wdb = node.require('walletdb');

  await node.open();

  const w = await wallet.create({ id: 'test' });

  console.log('Wallet:');
  console.log(w);

  // Fund default account.
  await fundWallet(wdb, w.account.receiveAddress);

  const balance = await wallet.getBalance();

  console.log('Balance:');
  console.log(balance);

  const acct = await wallet.createAccount('foo');

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
