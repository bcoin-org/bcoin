``` js
var bcoin = require('bcoin').set('testnet');

// SPV chains only store the chain headers.
var chain = new bcoin.chain({
  db: 'leveldb',
  location: process.env.HOME + '/spvchain',
  spv: true
});

var pool = new bcoin.pool({
  chain: chain,
  spv: true,
  maxPeers: 8
});

var walletdb = new bcoin.walletdb({ db: 'memory' });

pool.open().then(function() {
  return walletdb.open();
}).then(function() {
  return walletdb.create();
}).then(function(wallet) {
  console.log('Created wallet with address %s', wallet.getAddress('base58'));

  // Add our address to the spv filter.
  pool.watchAddress(wallet.getAddress());

  // Connect, start retrieving and relaying txs
  pool.connect().then(function() {
    // Start the blockchain sync.
    pool.startSync();

    pool.on('tx', function(tx) {
      walletdb.addTX(tx);
    });

    wallet.on('balance', function(balance) {
      console.log('Balance updated.');
      console.log(bcoin.amount.btc(balance.unconfirmed));
    });
  });
});
```