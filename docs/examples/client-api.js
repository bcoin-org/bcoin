'use strict';

const bcoin = require('../..');
const client = require('bclient');
const plugin = bcoin.wallet.plugin;
const network = bcoin.Network.get('regtest');

const node = new bcoin.FullNode({
  network: 'regtest',
  memory: true
});

node.use(plugin);

const walletClient = new client.WalletClient({
  port: network.walletPort
});

const nodeClient = new client.NodeClient({
  port: network.rpcPort
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

  // API call: walletClient.send('test', options)
  const tx = await walletClient.request('POST', '/wallet/test/send', options);

  return tx.hash;
}

async function callNodeApi() {
  // API call: nodeClient.getInfo()
  const info = await nodeClient.request('GET', '/');

  console.log('Server Info:');
  console.log(info);

  const json = await nodeClient.execute(
    'getblocktemplate',
    [{rules: ['segwit']}]
  );

  console.log('Block Template (RPC):');
  console.log(json);
}

(async () => {
  const wdb = node.require('walletdb').wdb;

  await node.open();

  // API call: walletClient.createWallet('test')
  const testWallet = await walletClient.request('PUT', '/wallet/test');

  console.log('Wallet:');
  console.log(testWallet);

  // open socket to listen for events
  await walletClient.open();

  // subscribe to events from all wallets
  walletClient.all();

  // Fund default account.
  // API call: walletClient.createAddress('test', 'default')
  const receive = await walletClient.request(
    'POST',
    '/wallet/test/address',
    {account: 'default'}
  );
  await fundWallet(wdb, receive.address);

  // API call: walletClient.getBalance('test', 'default')
  const balance = await walletClient.request(
    'GET',
    '/wallet/test/balance',
    {account: 'default'}
  );

  console.log('Balance:');
  console.log(balance);

  // API call: walletClient.createAccount('test', 'foo')
  const acct = await walletClient.request('PUT', '/wallet/test/account/foo');

  console.log('Account:');
  console.log(acct);

  // Send to our new account.
  const hash = await sendTX(acct.receiveAddress, 10000);

  console.log('Sent TX:');
  console.log(hash);

  // API call: walletClient.getTX('test', hash)
  const tx = await walletClient.request('GET', `/wallet/test/tx/${hash}`);

  console.log('Sent TX details:');
  console.log(tx);

  await callNodeApi();
  await walletClient.close();
  await node.close();
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
