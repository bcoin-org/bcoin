``` js
var bcoin = require('bcoin').set('main');

// Create a blockchain and store it in leveldb.
// `db` also accepts `rocksdb` and `lmdb`.
var prefix = process.env.HOME + '/my-bcoin-environment';
var chain = new bcoin.chain({ db: 'leveldb', location: prefix + '/chain' });

var mempool = new bcoin.mempool({ chain: chain });

// Create a network pool of peers with a limit of 8 peers.
var pool = new bcoin.pool({ chain: chain, mempool: mempool, maxPeers: 8 });

// Open the pool (implicitly opens mempool and chain).
(async function() {
  await pool.open();

  // Connect, start retrieving and relaying txs
  await pool.connect();

  // Start the blockchain sync.
  pool.startSync();

  // Watch the action
  chain.on('block', function(block) {
    console.log('Connected block to blockchain:');
    console.log(block);
  });

  mempool.on('tx', function(tx) {
    console.log('Added tx to mempool:');
    console.log(tx);
  });

  pool.on('tx', function(tx) {
    console.log('Saw transaction:');
    console.log(tx.rhash);
  });
})();

// Start up a segnet4 sync in-memory
// while we're at it (because we can).

var tchain = new bcoin.chain({
  network: 'segnet4',
  db: 'memory'
});

var tmempool = new bcoin.mempool({
  network: 'segnet4',
  chain: tchain
});

var tpool = new bcoin.pool({
  network: 'segnet4',
  chain: tchain,
  mempool: tmempool,
  size: 8
});

(async function() {
  await pool.open();

  // Connect, start retrieving and relaying txs
  await tpool.connect();

  // Start the blockchain sync.
  tpool.startSync();

  tchain.on('block', function(block) {
    console.log('Added segnet4 block:');
    console.log(block);
  });

  tmempool.on('tx', function(tx) {
    console.log('Added segnet4 tx to mempool:');
    console.log(tx);
  });

  tpool.on('tx', function(tx) {
    console.log('Saw segnet4 transaction:');
    console.log(tx);
  });
})();

```