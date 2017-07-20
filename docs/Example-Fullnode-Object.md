``` js
var bcoin = require('bcoin').set('main');

var node = bcoin.fullnode({
  checkpoints: true,
  // Primary wallet passphrase
  passsphrase: 'node',
  logLevel: 'info'
});

// We get a lot of errors sometimes,
// usually from peers hanging up on us.
// Just ignore them for now.
node.on('error', function(err) {
  ;
});

// Start the node
node.open().then(function() {
  // Create a new wallet (or get an existing one with the same ID)
  var options = {
    id: 'mywallet',
    passphrase: 'foo',
    witness: false,
    type: 'pubkeyhash'
  };

  return node.walletdb.create(options);
}).then(function(wallet) {
  console.log('Created wallet with address: %s', wallet.getAddress('base58'));

  node.connect().then(function() {
    // Start syncing the blockchain
    node.startSync();
  });

  // Wait for balance and send it to a new address.
  wallet.once('balance', function(balance) {
    // Create a transaction, fill
    // it with coins, and sign it.
    var options = {
      subtractFee: true,
      outputs: [{
        address: newReceiving,
        value: balance.total
      }]
    };
    wallet.createTX(options).then(function(tx) {
      // Need to pass our passphrase back in to sign!
      return wallet.sign(tx, 'foo');
    }).then(function(tx) {
      console.log('sending tx:');
      console.log(tx);
      return node.sendTX(tx);
    }).then(function() {
      console.log('tx sent!');
    });
  });
});

node.chain.on('block', function(block) {
  ;
});

node.mempool.on('tx', function(tx) {
  ;
});

node.chain.on('full', function() {
  node.mempool.getHistory().then(console.log);
});
```