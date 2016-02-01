# BCoin

**BCoin** is a bitcoin node which can act as an SPV node or a (semi-)fullnode.

## Install

```
$ npm install bcoin
```

## Example Usage

### Doing a full blockchain sync

``` js
var bcoin = require('bcoin');
var utils = bcoin.utils;

var pool = new bcoin.pool({
  // Number of peers to connect to
  size: 8,
  // Output debug messages
  debug: true,
  // We want a traditional full node sync
  type: 'full',
  // Use testnet
  network: 'testnet'
});

// Peer errors: they happen all the time.
pool.on('error', function(err) {
  utils.print('Error: %s', err.message);
});

// When a new block is added to the chain:
pool.on('block', function(block, peer) {
  // Give a progress report every 500 blocks
  if (pool.chain.height() % 500 === 0)
    utils.print('block=%s, height=%s', block.rhash, pool.chain.height());
});

// Start the get blocks sync
pool.startSync();
```

### Doing a fast SPV sync

``` js
var bcoin = require('bcoin');
var utils = bcoin.utils;
var fs = require('fs');

var pool = new bcoin.pool({
  // Number of peers to connect to
  size: 32,
  // Output debug messages
  debug: true,
  // We want an SPV sync using getheaders
  type: 'spv',
  // Use testnet
  network: 'testnet'
});

// Peer errors: they happen all the time.
pool.on('error', function(err) {
  utils.print('Error: %s', err.message);
});

// Instantiate an HD wallet with a serialized xprivkey
var wallet = new bcoin.wallet({
  hd: {
    xkey: process.env.XPRIVKEY || process.argv[2]
  }
});
utils.print('Opened wallet with address: %s', wallet.getAddress());

// Save our wallet for later
process.on('SIGINT', function() {
  fs.writeFileSync(
    process.env.HOME + '/my-wallet.json',
    JSON.stringify(wallet.toJSON()));
  process.exit(0);
});

// When a new block is added to the chain:
pool.on('block', function(block, peer) {
  // Give a progress report every 500 blocks
  if (pool.chain.height() % 500 === 0)
    utils.print('block=%s, height=%s', block.rhash, pool.chain.height());
});

// Watch for transactions pertaining to our wallet
pool.addWallet(wallet);

// Add watched transactions to our wallet's tx pool
pool.on('watched', function(tx, peer) {
  wallet.addTX(tx);
});

// Look for balance changes
wallet.on('balance', function() {
  utils.print('Wallet balance updated: %s', utils.btc(wallet.balance()));
});

// Start the getheaders sync
pool.startSync();
```

### Creating and sending a transaction

``` js
var bcoin = require('bcoin');
var utils = bcoin.utils;

// Create a pool in order to broadcast our transaction
var pool = bcoin.pool({
  size: 8,
  type: 'spv',
  network: 'testnet'
});

// Retrieve our fully synced wallet
var wallet = bcoin.wallet.fromJSON(require('./my-wallet.json'));
utils.print('Opened wallet with address: %s', wallet.getAddress());

// Create another wallet to send to
var receiver = bcoin.wallet();
utils.print('Created receiver wallet with address: %s', receiver.getAddress());

// Save our new wallet, lest we lose the funds
fs.writeFileSync(process.env.HOME + '/my-new-wallet.json',
  JSON.stringify(receiver.toJSON()));

// Create a transaction
var tx = bcoin.tx();

// Add an output, send some money to our new wallet
tx.output({
  address: receiver.getAddress(),
  // Every satoshi value in bcoin is
  // a big number, so we can convert
  // a BTC string to satoshis (big
  // number) by using utils.satoshi().
  // NOTE: BTC strings _must_ have
  // a decimal point.
  value: utils.satoshi('0.001')
});

// Fill the transaction inputs with the
// necessary unspents (hopefully we have them!).
tx.fillUnspent(
  wallet.unspent(),    // Our unspents to choose from
  wallet.getAddress(), // Our change address (warning: address re-use)
  null                 // We could put a hard fee here, but lets let bcoin figure it out
);

// Sign the transaction and place
// all signatures in necessary inputs
wallet.sign(tx);

// Make sure our transaction is valid.
if (!tx.verify())
  throw new Error('Our transaction did not verify!');

// Add our new TX to our wallets now
// that we know it is valid.
wallet.addTX(tx);
receiver.addTX(tx);

// Inspect our transaction before we send it.
utils.print('Sending transaction: %s', tx.rhash);
utils.print(tx);

// Tell our peers that we want to
// send a transaction across the network
pool.broadcast(tx)
  .on('ack', function(peer) {
    utils.print('Peer %s requested our transaction!', peer.host);
  })
  .on('reject', function(peer, details) {
    utils.print('Peer %s did not like our transaction (reason: %s).', peer.host, details.reason);
  });

// Watch for the transaction on the network
pool.watch(tx.hash());

// Wait to see our transaction on the network
pool.on('tx', function(ntx) {
  if (ntx.hash('hex') !== tx.hash('hex'))
    return;

  if (ntx.block)
    utils.print('Our tx was included in block %s (%d confirmations)', ntx.rblock, ntx.getConfirmations());
  else
    utils.print('Our tx is being propogated throughout the network!');

  // Add the network transaction to
  // our wallets to update the
  // confirmation status
  wallet.addTX(ntx);
  receiver.addTX(ntx);
});
```

### Multisig Transactions

Let's fabricate a 2-of-3 [escrow and dispute mediation][escrow] situation.

``` js
var bcoin = require('bcoin');
var utils = bcoin.utils;

var pool = bcoin.pool({
  size: 8,
  network: 'testnet'
});

var buyer = bcoin.wallet({
  type: 'scripthash',
  subtype: 'multisig',
  m: 2,
  n: 3
});

var seller = bcoin.wallet({
  type: 'scripthash',
  subtype: 'multisig',
  m: 2,
  n: 3
});

var mediator = bcoin.wallet({
  type: 'scripthash',
  subtype: 'multisig',
  m: 2,
  n: 3
});

buyer.addKey(seller.getPublicKey());
buyer.addKey(mediator.getPublicKey());

seller.addKey(buyer.getPublicKey());
seller.addKey(mediator.getPublicKey());

mediator.addKey(buyer.getPublicKey());
mediator.addKey(seller.getPublicKey());

// We should all have the same p2sh address
utils.assert(buyer.getScriptAddress() === seller.getScriptAddress());
utils.assert(buyer.getScriptAddress() === mediator.getScriptAddress());

utils.print('Created 2-of-3 wallet with address: %s', buyer.getScriptAddress());

// Create a fake coinbase for buyer to use as his funds
var coinbase = bcoin.tx().output(buyer.getKeyAddress(), utils.satoshi('50.0'));
buyer.addTX(coinbase);

// Now let's create a tx as the buyer.
// He wants to buy something from seller.
var btx = bcoin.tx();

// Send 25 BTC to the shared wallet
// to buy something from seller.
btx.output({
  address: buyer.getScriptAddress(),
  value: utils.satoshi('25.0')
});

// Fill the unspents and sign
buyer.fillUnspent(btx);
buyer.sign(btx);

// Buyer sends his funds to the 2-of-3 wallet
pool.broadcast(btx);

// Seller can now try to redeem the funds
seller.addTX(btx);

// Seller creates a new transaction
var stx = bcoin.tx();

// Seller wants to send the BTC to himself
stx.output({
  address: seller.getKeyAddress(),
  value: utils.satoshi('25.0')
    // Subtract the fee
    .sub(utils.satoshi('0.0001'))
    // Subtract the mediator's cut
    .sub(utils.satoshi('1.0'))
});

// Give the mediator a little something,
// since he's such a cool guy.
stx.output({
  address: mediator.getKeyAddress(),
  value: utils.satoshi('1.0')
});

// Add the buyer's utxo as the input
stx.input(btx, 0);

// Add _one_ signature to the tx
seller.sign(stx);

// The tx should not verify at this point
utils.assert(!stx.verify());

// Buyer/Scammer: Hey Mediator, I never got my thing.
// Mediator: That sucks. Let me talk to Seller.
// Seller: I gave Buyer the item.
// Here's the proof: [insert proof here],
// and here's my transaction: [stx.toRaw() here]
// Mediator: Cool, looks good. I'll sign it!
mediator.sign(stx);

// The tx should now verify.
utils.assert(stx.verify())

// Mediator broadcasts Seller's now
// fully-signed transaction. Seller
// gets money.
pool.broadcast(stx);
```

### Scripts

Bcoin has its own deserialized version of scripts to make them human-readable
and human-writable. For example, a standard pay-to-pubkey script would look
like:

``` js
tx.output({
  value: new bn(100000),
  script: [
    'dup',
    'hash160',
    hash, // Byte Array
    'equalverify',
    'checksig'
  ]
});
```

Opcodes are in the form of their symbolic names, in lowercase, with the `OP_`
prefixes removed. Pushdata ops are represented with Arrays.

The above script could be redeemed with:

``` js
tx2.input({
  out: { tx: tx, hash: tx.hash('hex'), index: 0 },
  seq: 0xffffffff,
  script: [
    signature, // Byte Array
    publicKey  // Byte Array
  ]
});
```

Executing a script by itself is also possible:

``` js
var stack = [];
bcoin.script.execute([[1], 'dup'], stack);
console.log(stack);

Output:
[[1], [1]]
```

#### Pushdata OPs

Note that with bcoins deserialized script format, you do not get to decide
pushdata on ops. Bcoin will always serialize to `minimaldata` format scripts in
terms of `OP_PUSHDATA0-OP_PUSHDATA4`.

`OP_0` is represented with an empty array (which is appropriate because this is
what gets pushed onto the stack). While `OP_1-16` are actually represented with
numbers. `OP_1NEGATE` is just '1negate'.

So a script making use of all pushdata ops would look like:

``` js
script: [
  [],                                // OP_0 / OP_FALSE
  1,                                 // OP_1 / OP_TRUE
  2, 3, 4, 5, 6, 7, 8, 9, 10,        // OP_2-10
  11, 12, 13, 14, 15, 16,            // OP_11-16
  '1negate',                         // OP_1NEGATE
  new Array(0x4b),                   // PUSHDATA0 (direct push)
  new Array(0xff),                   // PUSHDATA1
  new Array(0xffff),                 // PUSHDATA2
  new Array(0xffffffff)              // PUSHDATA4
];
```

##### Custom Scripts

Bcoin will allow you to use custom P2SH scripts, but it's up to you to
redeem/sign it property.

``` js
var wallet = bcoin.wallet({
  redeem: [
    1,
    '1add',
    'equal'
  ]
});
console.log(wallet.getScriptAddress());
var tx1 = bcoin.tx().output(wallet.getScriptAddress(), new bn(100000));
```

Which would be redeemed with:

``` js
tx2.input({
  out: { tx: tx1, hash: tx1.hash('hex'), index: 0 },
  script: [
    2,
    // Redeem script:
    wallet.getScript()
  ]
});
```

### Big Numbers

Bitcoin deals with really big numbers on a regular basis. Javascript Numbers
lose precision after 53 bits. It is absolutely necessary to use big numbers
when dealing with satoshi values.

``` js
var bcoin = require('bcoin');
var bn = bcoin.bn;

...

// Add an output with 100,000 satoshis as a value.
tx.output(wallet.getKeyAddress(), new bn(100000));
```

To make this easier to deal with, bcoin has two helper functions: `utils.btc()`
and `utils.satoshi()`.

``` js
// Convert a BTC string to Satoshis
var value = utils.satoshi('1.123');
console.log(value);
// Convert back to a BTC string
console.log(utils.btc(value));
```

Output:

``` js
<BN: 6b18fe0>
1.123
```

Note that BTC strings are identified by having a decimal point. They _must_
have a decimal point in order to be converted to satoshis by `utils.satoshi()`.

This will work:

``` js
var value = utils.satoshi('1.0');
```

This will __not__ work:

``` js
var value = utils.satoshi('1');
```

### Endianness

Everything in the bitcoin protocol is little-endian, including block hashes and
txids. Bcoin doesn't try to change this at all. If you're outputing a tx hash,
you will get the little-endian version.

You will not be able to find this hash on a blockchain explorer:

``` js
console.log(tx.hash('hex'));
```

The byte order must be reversed:

``` js
console.log(utils.revHex(tx.hash('hex')));
```

To make this easier, both tx and block objects have a quick `rhash` property:

``` js
// Output BE hashes as hex string - you will
// be able to find these on a blockchain explorer.
console.log(tx.rhash);
console.log(block.rhash);
```

### Arrays vs. Buffers

Every piece of binary data in bcoin that is user-facing in bcoin is an Array of
bytes. For example, `block.hash()` with no encoding passed in will return a
byte array.  Bcoin does use Buffers behind the scenes to speed up parsing of
blocks and transactions coming in through the network, but every piece of data
a programmer using bcoin will deal with is going to be a byte array.

### Saving transactions to a wallet

Most of the time, you won't need all transactions in the blockchain if you're
only building a wallet. When a transaction comes in pertaining to your wallet,
it's best to called `wallet.addTX(tx)` and save the wallet afterwards.

``` js
pool.on('watched', function(tx) {
  wallet.addTX(tx);
});

pool.on('full', function() {
  fs.writeFileSync(
    process.env.HOME + '/wallet.json',
    JSON.stringify(wallet.toJSON()));
});
```

### Saving the blockchain

At the moment, bcoin does not save any full blocks or make any assumptions
about how the programmer wants to do it. It only saves the blockchain (block
headers and chainwork). The programmer simply needs to hook into block events
and save the blocks.

``` js
pool.on('block', function(block) {
  // A simple key-value store:
  db.save(block.hash('hex'), utils.toHex(block.render()), function(err) {
    if (err)
      return console.error(err.message);
    console.log('Block %s saved.', block.rhash);
    // Could also save transactions individually here for quick lookups
  });
});
```

#### Handling Blockchain Forks

Bcoin handles blockchain forks like an SPV client. If it sees an alternate tip,
it will reset to the last non-forked block and kill the current peer while
emitting a `fork` event (see Pool events). It will repeat this process until
the network eventually chooses the best chain.

Bcoin essentially backs off and waits to see which fork wins. This means bcoin
plays no part in protecting the network by helping choose the best chain
according to the chainwork.

Note that this may _still_ cause an issue with transactions that are already
saved and considered confirmed. It's best to hook into the fork event and
remove all confirmed transactions you may have saved in your database.

``` js
pool.on('fork', function(tip1, tip2) {
  // Keep deleting everything until
  // the fork is resolved:
  db.get(tip1, function(err, block) {
    block.txs.forEach(function(tx) {
      db.remove(tx.hash('hex'));
    });
  });
  db.get(tip2, function(err, block) {
    block.txs.forEach(function(tx) {
      db.remove(tx.hash('hex'));
    });
  });
  db.remove(tip1);
  db.remove(tip2);
});
```

## API Documentation

### Objects

#### Block (from Object)

A deserialized bitcoin block object.

Usage: `bcoin.block([options], [subtype])`

Subtype can be `block`, `merkleblock`, or `header`.

##### Options:

- __version__ - Block version.
- __prevBlock__ - Previous block hash (hex string).
- __merkleRoot__ - Merkle root (hex string).
- __ts__ - Timestamp (unix time in seconds).
- __bits__ - Bits (target in compact form).
- __nonce__ - Nonce.
- __totalTX__ - Total TX (spv-only, and subtype=header only).
- __hashes__ - Hashes from partial merkle tree (spv-only).
- __flags__ - Flags from partial merkle tree (spv-only).
- __txs__ - Array of transactions (subtype=block only).
- __network__ - Whether this block came in through the network.
- __relayedBy__ - IP/host of relayer.

##### Properties:

- Inherits all from Object.
- All options.
- __tx__ - Type of the node (e.g. `box`).
- __valid__ - Cached preliminary verification return value.
- __chain__ - Chain object (default is the global chain).
- __rhash__ - Big-endian hash as a hex string (the byte order
  people are used to seeing). Useful for user output and debugging.
- __height__ - Block height in chain. `-1` if not in chain.
- __nextBlock__ - Next block hash as a hex string.
- __reward__ - Full reward with fees included (satoshis/big number).
- __fee__ - Total TX fees (satoshis/big number).
- __coinbase__ - Coinbase transaction.
- __entry__ - Corresponding `Entry` object in blockchain.
- __orphan__ - True if block's previous block is not in blockchain.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __hash([enc])__ - Hash the block headers, returns an array or a hex string
  (little-endian) if `enc='hex'`.
- __abbr()__ - Return a byte array of serialized headers.
- __render()__ - Return byte array of serialized block.
- __verify()__ - Do preliminary validation of block. Checks proof-of-work,
  timestamp limit, merkle root, max block size, etc.
- __verifyContext()__ - Do contextual block validation. Checks target, median
  time, outdated blocks, upgraded blocks, coinbase height, final TXes, verifies
  tx scripts. __NOTE__: The previous block __must__ be in the blockchain or the
  validation will fail.
- __isGenesis()__ - Returns true if block is the genesis block of the network.
  before the reference node.
- __getHeight()__ - Returns height in the blockchain. Returns `-1` if block is
  not present in the chain.
  node.
- __getNextBlock()__ - Returns hex string of the hash of the next block.
- __getBaseReward()__ - Return base reward in satoshis (big number).
- __getReward()__ - Return full reward with TX fees included in satoshis (big number).
- __getFee()__ - Return total TX fees in satoshis (big number).
- __getEntry()__ - Return corresponding `Entry` object in the blockchain.
- __isOrphan()__ - Returns true if the previous block is not in the blockchain.
- __getCoinbase()__ - Returns coinbase transaction.
- __toJSON()__ - Return serialized block in bcoin json format.

##### Static:

- __reward(height)__ - Calculate block reward based on a height.
- __fromJSON(json)__ - Return `Block` object from serialized JSON block format.

#### Bloom (from Object)

A bloom filter. Used internally by bcoin for SPV/filterload.

Usage: `bcoin.bloom(size, n, tweak)`

##### Methods:

- Inherits all from Object.
- __add(data, [enc])__ - Add an array or buffer to the bloom filter.
- __test(val, [enc])__ - Test the bloom filter against a piece of data.
  __NOTE:__ Bloom filters are probabilistic and may return false positives (but
  never false negatives).
- __reset()__ - Reset the bits in the bloom filter.

#### Chain (from EventEmitter)

The blockchain object. Used for block management. Stores `ChainBlock` entries
using `ChainDB`.

Usage: `bcoin.chain([options])`

##### Options:

- __debug__ - Whether to print debug messages.

##### Properties:

- Inherits all from EventEmitter.
- All options.
- __tip__ - The current tip of the blockchain as a `ChainBlock`.

##### Events:

- __fork__ - Emitted when a blockchain fork is detected. When a fork is seen,
  will kill the peer that forked and reset the tip to the last block which did
  not fork. Bcoin will repeat this process every time it sees an alternate tip.
  It will essentially back off and wait to see which fork wins the chainwork
  race.

##### Methods:

- Inherits all from Object.
- __resetLastCheckpoint()__ - Reset blockchain to the nearest checkpoint block.
- __resetHeight(height)__ - Reset the blockchain to a past height.
- __resetTime(ts)__ - Reset the blockchain to an approximate time (unix time
  in seconds). Bcoin will search the blockchain for a timestamp close to `ts`,
  and reset the chain to that height. Used in SPV syncs to get transactions for
  a wallet based on the wallet's last timestamp.
- __add(block, [peer])__ - Add a block to the block chain. Performs all block
  validation, fork recovery, orphan resolution, etc.
- __has(block/hash)__ - Returns true if chain contains hash as an entry or an
  orphan.
- __byHeight(height)__ - Return a `ChainBlock` entry by height.
- __byHash(block/hash)__ - Return a `ChainBlock` entry by hash.
- __byTime(ts)__ - Return a `ChainBlock` entry by ts. Bcoin will do a binary
  search for a block mined within an hour of `ts` (unix time in seconds).
- __hasBlock(hash)__ - Returns true if chain contains non-orphaned block.
- __hasOrphan(hash)__ - Return true if chain contains orphaned block.
- __getBlock(hash/height)__ - Return `ChainBlock` entry by height or hash.
- __getOrphan(hash)__ - Return orphaned `Block` object by hash.
- __isFull()__ - Returns true if last block in chained was mined within 40
  minutes of present time.
- __hashRange(startTime, endTime)__ - Return an array of block hashes between a
  range of time.
- __getLocator(hash/height)__ - Return array of block locator hashes
  starting from hash or height.
- __getOrphanRoot(block/hash)__ - Find the orphan root based on `hash` if there
  is one.
- __getHeight(block/hash)__ - Return block height based on hash or block.
- __getNextBlock(block/hash)__ - Return next block hash based on hash or block.
- __size()__ - Number of blocks in the chain (different from height).
- __height()__ - Return height of chain tip (`-1` if genesis block is not present).
- __currentTarget()__ - Return the current target in compact form.
- __target(last, [block])__ - Return the target (compact form) necessary for
  `block` based on `last` (its previous block).
- __toJSON()__ - Return serialized JSON form of chain.
- __fromJSON(json)__ - Add serialized blocks to chain.

##### Static:

- None.

#### ChainDB (from Object)

The blockchain database. Stores `ChainBlock` entries in a serialized binary
format. The same format as block headers (80 bytes), except an extra uint256 is
included at the end for chainwork, making each entry 112 bytes.

The ChainDB uses synchronous reads and asynchronous writes by default.

ChainDB caches the past `majorityWindow` blocks (1001 on main), or
`powDiffInterval` (2016 on main) blocks if `network.powAllowMinDifficulty` is
enabled. This is to speed up target calculation and `isSuperMajority` checks.

Usage: `bcoin.chaindb(chain, options)`

##### Options:

- __file__ - Database file (`~/bcoin-[network]-blockchain.db` by default).

##### Properties:

- Inherits all from Object.
- All options.
- __size__ - Size in bytes of the DB file.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __count()__ - Number of total records (different from chain height).
- __get(height)__ - Get ChainBlock entry synchronously.
- __getAsync(height, callback)__ - Get ChainBlock entry asynchronously (used
  for initial blockchain load).
- __save(entry, [callback])__ - Save ChainBlock entry asynchronously.
- __saveSync(entry)__ - Save ChainBlock entry synchronously.
- __has(height)__ - Returns true if ChainDB has a block at this height.
- __getSize()__ - Get size in bytes of DB file.

##### Static:

- Inherits all from Object.
- None.

#### ChainBlock (from Object)

An "entry" for the blockchain. Counterpart to the `block` object with some
different properties and methods. ChainBlocks are part of the blockchain's
entire linked list.

##### Options:

- __version__ - Block version.
- __prevBlock__ - Previous block hash (hex string).
- __merkleRoot__ - Merkle root (hex string).
- __ts__ - Timestamp (unix time in seconds).
- __bits__ - Bits (target in compact form).
- __nonce__ - Nonce.
- __chainwork__ - Amount of chainwork (big number). __NOTE__: Will be
  calculated based on `proof` and previous block's chainwork if not present.

##### Properties:

- Inherits all from Object.
- All options.
- __prev__ - Previous ChainBlock entry.
- __next__ - Next ChainBlock entry.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __getProof()__ - Calculate and return proof based on bits/target (big number).
- __getChainwork()__ - Calculate and return chainwork based on proof and
  previous block's chainwork.
- __getMedianTime()__ - Get the median time for the block.
- __isOutdated(version)__ - Check if block version is outdated (calls
  `isSuperMajority`).
- __isUpgraded(version)__ - Check if block version upgrades the blockchain
  (calls `isSuperMajority`).
- __isSuperMajority(version, required)__ - Calculate if the last
  `majorityWindow` blocks are of `version`.
- __toJSON()__ - Return serialized ChainBlock in JSON format.
- __toRaw()__ - Return serialized ChainBlock in binary ChainDB format.

##### Static:

- Inherits all from Object.
- __fromJSON(json)__ - Return ChainBlock from serialized JSON format.
- __fromRaw(data)__ - Return ChainBlock from ChainDB binary format.

#### HDSeed (from Object)

Generate an HDSeed (potentially from a passed-in mnemonic) for HD key
generation.

Usage: `bcoin.hd.seed([options])`

##### Options:

- __bits__ - Bits of entropy (default: 128).
- __entropy__ - Entropy bytes (will be generated from /dev/urandom if entropy
  is not present).
- __mnemonic__ - English word mnemonic. Will be generated randomly using
  `entropy` if not present.
- __passphrase__ - Passphrase for pbkdf2 seed.

##### Properties:

- Inherits all from Object.
- All options.
- __seed__ - pbkdf2 seed.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __createSeed(passphrase)__ - Create pbkdf2 seed from options.

##### Static:

- Inherits all from Function.
- __create(options)__ - Create and generate seed.

#### HDPrivateKey/HDPublicKey (from Object)

Generate an HDSeed (potentially from a passed-in mnemonic) for HD key
generation.

Usage: `bcoin.hd.priv([options])` or `bcoin.hd.pub([options])`

##### Options:

- All options from HDSeed for seed generation.
- __seed__ - HDSeed for generation (will be generated randomly if no options
  are present).
- __xkey__ - Serialized xprivkey base58 string.

Deserialized option data:

- __depth__
- __parentFingerPrint__
- __childIndex__
- __chainCode__
- __privateKey__
- __publicKey__
- __checksum__

##### Properties:

- Inherits all from Object.
- All options.
- __data__ - Normalized and deserialized data.
- __hdpub__ - Corresponding HDPublicKey object (present on HDPrivateKeys only).
- __xpubkey__ - Serialized xpubkey base58 string.
- __xprivkey__ - Serialized xprivkey base58 string.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __derive(index/path, [hardened])__ - Returns a child key from `index` or
  `path`.

##### Static:

- Inherits all from Function.
- None.

#### Input (from Object)

TX Input object.

Usage: `bcoin.input([options])`

##### Options:

- __out.tx__ - Reference to the previous output's transaction (optional).
- __out.hash__ - Previous output's txid as a hex string.
- __out.index__ - Previous output's index.
- __script__ - Array of opcodes.
- __seq__ - Input's nSequence, `0xffffffff` by default.

##### Properties:

- Inherits all from Object.
- All options.

###### Getters

TX inputs are primitive by themselves, containing most of their relevant data
in the `script` or previous output. The Input object contains several getters
which parse the script and grab the previous output data and cache it as
`_data`.

- __type__ - Standard transaction type of previous output (`pubkey`,
  `pubkeyhash`, `multisig`, `scripthash`, or `nulldata`). `nulldata` will never
  be the type of an input as `nulldata` outputs can never be redeemed.
- __subtype__ - Only present on `scripthash` transactions. The "real" transaction
  type of the previous output. See list above.
- __signature__ - The first signature in the input script.
- __key__ - The first public key in the input script.
- __hash__ - The scripthash or the first public key hash in the input script (if
  only public keys / redeem scripts are present, they will be hashed).
- __address__ - Scripthash address, first public key address, or a generated ID
  if no addresses are found (useful for making a blockchain explorer).
- __signatures__ - Array containing all signatures in the input.
- __keys__ - Array containing all keys in the input/previous-output.
- __hashes__ - Array containing all public key hashes in input/previous-output
  (all keys will be hashed if there are no hashes present).
- __addresses__ - All hashes/keys as addresses.
- __redeem__ - The redeem script in its deserialized form.
- __scripthash__ - The hash of the redeem script.
- __scriptaddress__ - The p2sh address.
- __m__ - `m` value (required signatures).
- __n__ - `n` value (number of keys).
- __lock__ - The OP_CHECKLOCKTIMEVERIFY locktime if present (NOTE: This will only
  grab the first value and not deal with OP_IF statements, etc).
- __flags__ - Coinbase flags if present.
- __text__ - Coinbase flags converted to UTF-8, if present.
- __output__ - Previous Output object.
- __value__ - Value (satoshis/big number) of the previous output.
- __tx__ - Reference to the previous output's parent transaction.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __getID()__ - Generate an ID string for the input. Used internally if no
  `address` is found.

##### Static:

- Inherits all from Function.
- __getData(input)__ - Parse input / previous output and grab all data used for
  getters.

#### Output (from Object)

TX Output object.

Usage: `bcoin.output([options])`

##### Options:

- __script__ - Output script.
- __value__ - Value of output in satoshis (big number).

##### Properties:

- Inherits all from Object.
- All options.

###### Getters

TX outputs are primitive by themselves, containing most of their relevant data
in the `script`. The Output object contains several getters which parse the
script and cache it as `_data`.

- __type__ - Standard transaction type of output (`pubkey`, `pubkeyhash`,
  `multisig`, `scripthash`, or `nulldata`).
- __subtype__ - Only present on `scripthash` transactions. The "real" transaction
  type of the output.
- __signature__ - Null.
- __key__ - The first public key in the script.
- __hash__ - The scripthash or the first public key hash in the output script (if
  only public keys / redeem scripts are present, they will be hashed).
- __address__ - Scripthash address, first public key address, or a generated ID
  if no addresses are found (useful for making a blockchain explorer).
- __signatures__ - Empty array.
- __keys__ - Array containing all keys in the output script.
- __hashes__ - Array containing all public key hashes in output
  (all keys will be hashed if there are no hashes present).
- __addresses__ - All hashes/keys as addresses.
- __redeem__ - Null.
- __scripthash__ - The hash of the redeem script.
- __scriptaddress__ - The p2sh address.
- __m__ - `m` value (required signatures).
- __n__ - `n` value (number of keys).
- __lock__ - The OP_CHECKLOCKTIMEVERIFY locktime if present (NOTE: This will only
  grab the first value and not deal with OP_IF statements, etc).
- __flags__ - `nulldata` data.
- __text__ - `nulldata` data converted to UTF-8.

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __getID()__ - Generate an ID string for the output. Used internally if no
  `address` is found.

##### Static:

- Inherits all from Function.
- __getData(output)__ - Parse output script and grab all data used for getters.

#### Miner (from EventEmitter)

A CPU bitcoin miner built on top of bcoin.

Usage: `bcoin.miner([options])`

##### Options:

- __address__ - Where to send the coinbase reward.
- __msg__ - Optional message to put in the coinbase script (default: `mined by
  bcoin`).

##### Properties:

- Inherits all from EventEmitter.
- All options.
- __hashes__ - Number of hashes since the start of mining the current block
  (big number).
- __rate__ - Hash rate.

##### Events:

- __block__ - Block object received when a new block is mined. __NOTE:__ Miner
  will automatically attempt to broadcast the blocks, but it might be wise to
  save them yourself as a failsafe.
- __status__ - A progress report sent every 100000 hashes, containing
  `hashrate`, `hashes`, `target`, `height`, and `best` (current tip hash).

##### Methods:

- Inherits all from Object.
- __start()__ - Start mining. Will block the thread until the nonce overflows
  (after which it times out for 10ms before incrementing the extraNonce in
  order to receive more transactions and potentially a new tip).
- __stop()__ - Stop mining.
- __add(block/tx)__ - Add a new tip or a new transaction to the block.
- __addBlock(block)__ - Inform the miner that someone beat us to the punch.
  Start over with a new block.
- __addTX(tx)__ - Add a transaction to the block being mined.

##### Static:

- Inherits all from Function.

#### Peer (from EventEmitter)

Peer object. Used internally by the Pool object.

Usage: `bcoin.peer(pool, createConnection, options)`

- __pool__: Pool object.
- __createConnection(peer, pool, options)__: Callback which must return a
  node-like socket.

##### Options:

- __backoff__ - Time to delay socket creation in milliseconds.

##### Properties:

- Inherits all from EventEmitter.
- All options.
- __socket__ - Socket object.
- __parser__ - Parser object for peer.
- __framer__ - Framer object for peer.
- __version__ - Reference to the version packet received from peer.
- __destroyed__ - Whether the peer has been destroyed.
- __ack__ - Whether a `verack` has been received.
- __connected__ - Whether the socket has established a connection.
- __ts__ - Time in unix seconds of connection time.
- __host__ - Hostname/IP string.
- __port__ - Port.
- __bloom__ - Reference to the bloom filter (SPV-only).

##### Events:

- __socket__ - Received on socket creation if `backoff` option was specified.
- __connect__ - Received on socket connection.
- __ack__ - Received on `verack` packet.
- __close__ - Received on peer destruction.
- __error__ - Received on error.
- __[packetname]__ - Received on packet (see Packet List).

##### Methods:

- Inherits all from EventEmitter.
- __broadcast(items)__ - Broadcast array of items, whether they be blocks or
  TXes. Will send an `inv` packet to all peers and wait for `getdata` requests.
- __updateWatch()__ - Resend `filterload` packet. Useful after adding data to
  the bloom filter (SPV-mode only).
- __getData(items)__ - Request blocks or TXes.
- __loadMempool()__ - Send `mempool`. Requests `inv` packet full of mempool
  transactions from peer.
- __loadHeaders(hashes, stop)__ - Send `getheaders`.
- __loadBlocks(hashes, stop)__ - Send `getblocks`.

##### Static:

- Inherits all from Function.

#### Pool (from EventEmitter)

A pool of peers. The heart and soul of bcoin's network activity.

Usage: `bcoin.pool(options)`

Pool will connect to one `loader` peer and `options.size` number of `block`
peers. The `loader` peer is for `getblocks` or `getheaders` (as well as
`getdata`, but only on a traditional `getblocks` sync). The `block` peers are
used for `getdata` (on a non-traditional sync) as well as for broadcasting
blocks/txes and receiving broadcasted blocks/txes.

The pool object will handle DoS attempts, label peers as misbehaving and ban
them if necessary. If the pool does not receive an verack packet from a peer
after a specified amount of time, the peer will be killed and a new one will be
found. If the pool does not receive a block or inv packet in a specified amount
of time, the loader peer will be killed and a new one will be found.

The pool object currently does not listen on a socket. It cannot accept
connections (it can only connect to peers). It also doesn't maintain a mempool.
In this way, the bcoin pool object is a "selfish" node. It does not help
propogate data throughout the network.

##### Options:

- __debug__ - If true, output debug messages.
- __network__ - Which builtin network to use. Can be `main`, `testnet`, or
  `regtest`.
- __fullNode__ - If true, download blockchain using the traditional `getblocks`
  method with no `filterload` functionality. If false, do an SPV sync using
  `getheaders` and `filterload`.
- __type__ - Can be `spv` or `full` (same as `fullNode=false`, and
  `fullNode=true` respectively).
- __headers__ - Force use of `getheaders` for blockchain download depending on
  boolean value.
- __multiplePeers__ - Force downloading of blocks from multiple peers depending
  on value (__NOTE:__ only works with a `getheaders` sync).
- __relay__ - Relay value in `version` packet. See BIP-37 for details.
- __createSocket(port, host)__ - Callback to create a socket. Must return a
  node-like socket.
- __seeds__ - List of initial seeds (array of strings in the format of
  `{ipv4/host}:{port}` or `[{ipv6}]:port`). Port will be set to the default
  network port if not present.
- __discoverPeers__ - If `false`, pay no attention to `addr` packets. Only
  connect to default seeds or seeds passed in with `seeds`.
- __size__ - Size of pool i.e. the number of peers to maintain connections
  with.
- __loadTimeout__ - The amount of time (ms) before killing the loader peer if
  an `inv` or `block` packet has not been received (default: 30000).
- __loadInterval__ - The amount of time (ms) before attempting stall recovery
  on the loader peer (which sends another `getblocks`/`getheaders`) (default:
  5000).
- __requestTimeout__ - timeout before retrying a request (default: 10000).
- __invTimeout__ - Amount of time before removing objects from the broadcasted
  `inv` list (default: 60000).
- __wallets__ - Array of wallets to "watch" for on the pool (SPV-only).

##### Properties:

- Inherits all from EventEmitter.
- All options.
- __chain__ - Reference to the Chain object for the pool.
- __syncing__ - Whether the pool is syncing the blockchain.
- __synced__ - Whether the pool has completed the initial blockchain sync.
- __peers.block__ - Array of block peers.
- __peers.pending__ - Block peers in the process of establing a connection.
- __peers.load__ - Loader peer.
- __peers.all__ - Array of all peers.
- __block.bestHeight__ - Highest height received from `version` packet
  (__NOTE:__ Not trustworthy).
- __block.bestHash__ - The last known best hash from the loader peer (the last
  hashContinue in a getblocks sync, or the last header hash in a getheaders
  sync).
- __inv.list__ - List of currently broadcasted items.

##### Events:

- __load()__ - Received once chain is done loading.
- __block(block, peer)__ - Received when a new block is received from peer and
  to the chain.  (__NOTE:__ this will never emit orphans).
- __pool block(block, peer)__ - Received when any new and valid block is
  received from a peer.
- __tx(tx, peer)__ - Received on transaction.
- __watched(tx, peer)__ - Received when a watched transaction is received
  (SPV-only).
- __fork(tip1Hash, tip2Hash)__ - Received on fork notifying the user to
  potentially ignore transactions in the forked blocks.
- __full()__ - Received when the blockchain is full.
- __headers(payload)__ - `getheaders` payload.
- __blocks(items)__ - `inv` payload containing only block hashes.
- __chain-progress(fillPercent, peer)__ - Received on a new block.
- __error(err, [peer])__ - Received on error (usually a peer error).
- __reject(payload, peer)__ - Received when a peer rejects a broadcasted
  block/TX.
- __addr(payload, peer)__ - Received when an `addr` packet is received.
- __txs(txs, peer)__ - Received on `inv` packet, containing only TX hashes.
- __version(payload, peer)__ - Received on peer `version` packet.
- __peer(peer)__ - Received when a new peer is added.

##### Methods:

- Inherits all from EventEmitter.
- __startSync()__ - Start downloading the blockchain.
- __stopSync()__ - Pause the blockchain sync.
- __isFull()__ - Whether the blockchain is full. Calls `chain.isFull()`.
- __loadMempool()__ - Request mempool transactions from all peers.
- __watch(id)__ - Add a piece of data to "watch" for to the bloom filter. Send
  updated `filterload` to peers (SPV-only).
- __unwatch(id)__ - Stop watching for `id` (SPV-only).
- __isWatched(tx)__ - Test a transaction to see if the pool's bloom filter was
  watching for it (SPV-only).
- __addWallet(wallet)__ - Add a Wallet object to watch for. Add's wallet's
  pubkey, pubkeyhash, redeem script, and scripthash to the bloom filter. Resets
  the blockchain to the timestamp of the last TX the wallet contains in its
  TXPool (SPV-only).
- __removeWallet(wallet)__ - Remove wallet from watch list (SPV-only).
- __search([id], range)__ - Search a timestamp range, watch for `id`
  (SPV-only). `range` is a timestamp range: `{ start: unixSeconds, end:
  unixSeconds }`.
- __getBlock(hash, callback)__ - Request block from peer.
- __sendBlock(block)__ - Broadcast a block.
- __getTX(txid, range, callback)__ - Attempt to search for a particular
  transaction (SPV-only). `range` is a timestamp range: `{ start: unixSeconds,
  end: unixSeconds }`.
- __sendTX(tx)__ - Broadcast a transaction.
- __broadcast(block/tx)__ - Broadcast block or TX.
- __destroy()__ - Destroy pool and peers.
- __getPeer(host)__ - Get peer by host/ip+port.
- __addSeed(host)__ - Add a seed to the seed list.
- __removeSeed(host)__ - Remove a seed from the seed list.
- __setMisbehavior(peer, dos)__ - Increase peer's banscore by `dos`.
- __isMisbehaving(peer/host)__ - Whether peer is known for misbehaving.

##### Static:

- Inherits all from Function.


#### script

A collection of functions for script handling.

Usage:

- `s = bcoin.script.decode(rawScript)`
- `rawScript = bcoin.script.encode(s)`

##### Functions:

- __decode(s)__ - Decode a raw script into bcoin's deserialized format (an
  array of strings and arrays).
- __encode(s)__ - Encode a deserialized script to a raw byte array.
- __normalize(s)__ - Normalize a script by changing `0` into `[]`, `-1` into
  `'1negate'`, etc. Currently unused.
- __verify(input, output, tx, index, flags)__ - Execute input and previous
  output script and verify input. `index` is the index of the input being
  verified. `flags` is an object with boolean values. Keys can be of any of
  bitcoind's script flags in lowercase. i.e. `minimaldata`, `cleanstack`, etc.
- __getSubscript(s, lastSep)__ - Return script from `lastSep` with
  codeseparators removed.
- __checksig(msg, sig, key)__ - Verify a signature against a hash and key.
- __sign(msg, key, type)__ - Create a bitcoin ecdsa signature from `msg` and a
  private key. Appends `type` to the signature (the sighash type).
- __execute(s, stack, tx, index, flags)__ - Execute a script. `stack` must be
  an array.
- __bool(value)__ - Cast a byte array to bool. Mimics bitcoind's
  `CastToBool()` function. Checks for negative zero.
- __num(value, [useNum], [minimaldata])__ - Create a standard little-endian big
  number from `value`. Checks for `minimaldata` if true. Checks for negative
  zero, etc.  Mimics bitcoind's CScriptNum. If `useNum` is `true`, attempt to
  return a javascript Number.
- __array(value)__ - Convert big number to script little endian byte array.
- __createMultisig(keys, m, n)__ - Compile a standard multisig script from
  array of keys and `m` and `n` value.
- __createScripthash(s)__ - Compile a scripthash script from `s`.
- __getRedeem(s)__ - Grab an deserialize redeem script from input script.
- __getType(s)__ - Return standard output script type. `unknown` if unknown.
- __size(s)__ - Return script size in bytes.
- __isLocktime(s)__ - Returns true if script is a checklocktimeverify script.
- __getLockTime(s)__ - Return locktime value pushed onto the stack if
  checklocktimeverify is used.
- __getInputData(s, [prev])__ - Parse input and previous output scripts.
  Extract as much data as possible. Same format as `Input` getters.
- __getOutputData(s)__ - Parse output script. Extract as much data as possible.
  Same format as `Output` getters.
- __getUnknownData(s)__ - Parse script and look for chunks of data with valid
  key and signature encodings. Return all keys and signatures. Same format as
  `getInputData` and `getOutputData`.
- __isPubkey(s)__ - Returns true if script is pay-to-pubkey.
- __isPubkeyhash(s)__ - Returns true if script is pay-to-pubkeyhash.
- __isMultisig(s)__ - Returns true if script is multisig.
- __isScripthash(s)__ - Returns true if script is pay-to-scripthash.
- __isNulldata(s)__ - Returns true if script is nulldata.
- __getInputType(s)__ - Same as `script.getType()`, but works on input
  scripts.
- __isPubkeyInput(s)__ - Returns true if script is pay-to-pubkey input script.
- __isPubkeyhashInput(s)__ - Returns true if script is pay-to-pubkeyhash input
  script.
- __isMultisigInput(s)__ - Returns true if script is multisig input script.
- __isScripthashInput(s)__ - Returns true if script is pay-to-scripthash input
  script.
- __getCoinbaseData(s)__ - Extract as much data as possible from a coinbase
  script including `height`, `extraNonce`, `flags`, and `text`.
- __isHash(data)__ - Returns true if data is the length of a ripemd hash.
- __isKey(data)__ - Returns true if data is the length of a public key.
- __isSignature(data)__ - Returns true if data is the length of a signature.
- __isDummy(data)__ - Returns true if data is a null dummy (empty array).
- __isData(data)__ - Returns true if data is potentially a nulldata.
- __isValidKey(data, [flags])__ - Returns true if data is of strict key
  encoding.
- __isKeyEncoding(data)__ - Returns true if data is correct key encoding.
- __isValidSignature(data, [flags])__ - Returns true if data is of signature
  encoding, with a low DER S value and has a valid hash type.
- __isSignatureEncoding(sig)__ - Returns true if `sig` is correct signature
  encoding (BIP-66).
- __isHashType(sig)__ - Returns true if sig has a valid hash type.
- __isLowDER(sig)__ - Returns true if sig has a low S value.
- __format(s)__ - Format script to make it more human-readable for output and
  debugging.
- __isPushOnly(s)__ - Returns true if script contains only push opcodes.
- __getSigops(s, [accurate])__ - Count number of sigops in script. Legacy
  counting by default. Set `accurate` to true for accurate counting.
- __getScripthashSigops(s)__ - Count sigops in scripthash input + redeem
  script.
- __getArgs(s)__ - Return number of expected "input args" for output script
  type.

#### TXPool (from EventEmitter)

A pool of transactions which can be used in conjuction with a wallet object to
calculate which transactions have been spent and which are unspent, ultimately
calculating a `balance`. Used internally by Wallet object.

Usage: `bcoin.txPool(wallet)`

##### Properties:

- Inherits all from EventEmitter.
- None.

##### Events:

- __error(err)__ - Emitted on error.
- __load()__ - Emitted when storage has finished loading.
- __update(lastTs, tx)__ - Emitted when a spending transaction is added to the
  pool.
- __tx(tx)__ - Emitted when tx is added to the pool.

##### Methods:

- Inherits all from EventEmitter.
- __add(tx)__ - Add TX to the pool.
- __all()__ - Return all TXes in the pool owned by wallet.
- __unspent()__ - Return all TXes with unspent outputs, owned by wallet.
- __pending()__ - Return all 0-confirmation transactions.
- __balance()__ - Return total balance of TX pool.
- __toJSON()__ - Return TX pool in serialized JSON format.
- __fromJSON()__ - Load TX pool from serialized JSON format.

##### Static:

- Inherits all from Function.


#### TX (from Object)

TX object.

Usage: `bcoin.tx([options], [block])`

##### Options:

- __version__ - Transaction version (default: 1).
- __inputs__ - Array of input objects with `tx.input()` options.
- __outputs__ - Array of output objects with `tx.output()` options.
- __lock__ - nLockTime value.
- __ts__ - Timestamp (set by `block` if passed in arguments - spv-mode).
- __block__ - Block hash (Set by `block` if passed in arguments - spv-mode).
- __network__ - Should be `true` if TX came in from the network.
- __relayedBy__ - IP/hostname of peer who relayed this TX.
- __unspent__ - List of unspents to use to fill the transaction inputs.
- __hardFee__ - Custom fee to use in satoshis (big number) (optional).
- __changeAddress__ - Address to send change to.
- __changeIndex__ - Index of the change output.

##### Properties:

- Inherits all from Object.
- All options.
- __ps__ - Pending since time. Time of local transaction creation. Present only
  if this transaction is not in a block yet.
- __chain__ - Reference to the `chain` object.
- __rblock__ - Big-endian hex string of TX's `block` hash.
- __rhash__ - Big-endian hex string hash of transaction.
- __fee__ - Transaction fee in satoshis (big number).
- __value__ - Total value on the output side in satoshis (big number).
- __height__ - Height of block TX was included in (`-1` if not included).
- __confirmations__ - Number of confirmations.
- __priority__ - Transaction priority based on input age and size (big number).

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- __clone()__ - Return an exact duplicate of the transaction.
- __hash([enc], [force])__ - Return TX hash/id. Hashes raw data passed in from
  the network if available to avoid reserialization. Pass in `force=true` if
  the transaction was mutated to get the current hash.
- __render([force])__ - Serialize transaction. Returns raw byte array. Will
  return raw data passed in from the network if available. Set `force=true` to
  force serialization.
- __size()__ - Return serializzed transaction size in bytes.
- __input(options)__ - Add an input to the transaction. Options can be an Input
  object (see above), in the form of an Input object (containing properties
  `out.tx`, `out.hash`, `out.index`, `script`, and `seq`).
  - `input()` can handle many different arguments in the forms of:
    - `tx.input(tx, index)`
    - `tx.input(txHash, index)`
    - `tx.input(input)`
    - `tx.input({ hash: hash, index: index })`
    - `tx.input({ tx: tx, index: index })`
- __scriptInput(index/input, pub, redeem)__ - Initialize the input scripts
  based on previous output script type. `n` signatures will be added.
  Signatures will be null dummies (empty signature slots) until `signInput()`
  is called. `pub` (the public key) and `redeem` (raw redeem script) should
  always be passed in if there is a pubkeyhash or scripthash output being
  redeemed. Will not overwrite existing input scripts.
- __signature(index/input, key, [type])__ - Create a signature for the desired
  input using `key` as the private key and `type` as the sighash type. Sighash
  type can be a number or a string (`all`, `single`, or `none`). Returns a DER
  signature byte array.
- __signInput(index/input, key, [type])__ - Sign the desired input and place
  the signature in an empty signature slot. Finalize the input script and
  reduce signature slots to `m` once the minimum amount of signatures has been
  reached.
- __scriptSig(index/input, key, pub, redeem, type)__ - Execute `scriptInput`
  _and_ `signInput`.
- __output(options), output(output), output(address, value)__ - Add an output to the
  transaction.
  - `options` can be in the form of:

                {
                  value: [satoshis/big number],
                  script: [deserialized script],
                  address: [pubkey address or scripthash address],
                  keys: [array of keys],
                  m: [m value],
                  n: [n value],
                  flags: [nulldata],
                  scripthash: [true or false],
                  lock: [locktime for checklocktimeverify]
                }

- __scriptOutput(index/output, options)__ - Compile an output script for the
  output based on the same options `output()` handles.
- __signatureHash(index/input, s, type)__ - Return the to-be-signed hash of the
  transaction for the desired input. Must pass in previous output subscript as
  `s`, as well as the sighash type (number or string of `all`, `none`, or
  `single`).
- __verify([index], [force], [flags])__ - Execute and verify the desired input
  script. If no index is passed in, all inputs will be verified. `verify()`
  will not verify TXes already included in blocks, set `force=true` to force
  verification. `flags` can be any of the bitcoind script flags in lowercase,
  i.e. `{ cleanstack: false }`. They are all enabled by default. Returns true
  if verification succeeded.
- __isCoinbase()__ - Returns true if TX is a coinbase.
- __maxSize()__ - Estimate the size of the transaction in bytes (works before
  input scripts are compiled and signed). Useful for fee calculation.
- __getUnspent(unspent, changeAddress, [fee])__ - Determine which unspents to
  use from `unspent` (an array of possible unspents, usually returned by
  `wallet.unspent()`). Calculates the fee and chooses unspents based on the
  total value required for the transaction. A hard `fee` can be passed in
  (satoshis/big number) which will skip the fee calculation. Calculates the
  necessary change. Returns an object in the form of:

        {
          inputs: [array in inputs to add],
          change: [change in satoshis (big number)],
          cost: [total cost minus fee in satoshis (big number)],
          fee: [fee for transaction in satoshis (big number)],
          total: [total cost including fee in satoshis (big number)],
          kb: [total kb for fee calculation]
        }

  `inputs` will be `null` if not enough funds were available.
  __NOTE:__ `getUnspent()` should only be called once all outputs have been added.
- __fillUnspent(unspent, [changeAddress], [fee])__ - Calls `getUnspent()` and
  adds the created inputs to the transaction. Adds a change output if
  necessary. Returns the same result value as `getUnspent()`. __NOTE:__ Should
  only be called once all outputs have been added.
- __getFee()__ - Returns the fee for transaction.
- __funds(side)__ - Returns the total funds for a side of the transaction
  `'in'` or `'out'`.
- __setLockTime(lock)__ - Sets a locktime for the transaction. Will set the
  nSequences accordingly.
- __increaseFee(fee)__ - Increase fee to a hard fee. Opts transaction in for
  replace-by-fee. __NOTE:__ Transaction must be rescripted and resigned before
  broadcasting.
- __fill(wallet/txpool/object)__ - Fills all the transaction's inputs with the
  appropriate previous outputs using the available transactions in a wallet,
  txpool, or an object with txids as its keys and txs as its values.
- __isFull()__ - Returns true if the TX has all previous output references.
- __isFinal(height, ts)__ - Mimics the bitcoind `IsFinalTx()` function. Checks
  the locktime and input sequences. Returns true or false.
- __getSigops([scripthash], [accurate])__ - Count sigops in transaction. Set
  `scripthash=true` to count redeem script sigops. Set `accurate=true` for
  accurate counting instead of legacy counting.
- __isStandard()__ - Mimics bitcoind's `IsStandardTx()` function.
- __isStandardInputs()__ - Mimics bitcoind's `IsStandardInputs()` function.
- __getPriority()__ - Calculate transaction priority based on input age.
  Returns a big number.
- __isFree()__ - Determines whether transaction needs a fee or not based on
  priority and size. Returns true if tx needs no fee.
- __getHeight()__ - Returns the height of the block TX was included in, similar
  to `GetDepthInMainChain()`. Returns `-1` if no block is found.
- __getConfirmations()__ - Returns number of confirmations.
- __getValue()__ - Returns total value on the output side.
- __toJSON()__ - Return serialized TX in bcoin JSON format.
- __toRaw()__ - Returns serialized TX in standard bitcoin binary format.

##### Static:

- Inherits all from Function.
- __fromJSON(json)__ - Return TX from serialized JSON format.
- __fromRaw(data)__ - Return TX from standard bitcoin binary format.

#### Wallet (from EventEmitter)

Wallet object.

Usage: `bcoin.wallet(options)`

##### Options:

- __compressed__ - Whether to use compressed public keys (default: true).
- __label__ - A string identifier for this wallet. Will be saved in JSON format.
- __changeAddress__ - A change address for this wallet to use (warning: address re-use).
- __key__ - Can be an instance of elliptic.KeyPair, bcoin.hd.priv, or bcoin.hd.pub.
- __priv__ - Private key, can be an array of bytes.
- __pub__ - Public key, can be an array of bytes.
- __type__ - Output script type. Can be: `pubkey`, `pubkeyhash`, `multisig`, `scripthash`.
- __subtype__ - Only applicable for `scripthash` types. Specify the type of
  redeem script. Can be `pubkey`, `pubkeyhash`, or `multisig`.
- __keys__ - An array of public keys (usually byte arrays) to use for a
  multisig wallet.
- __m__ - `m` value of wallet (number of required signatures).
- __n__ - `n` value of wallet (number of keys).
- __redeem__ - A script array containing a custom redeem script for
  `scripthash`.
- __hd__ - Make the wallet HD. Can be an object containing HDPrivateKey
  options, or a boolean.

##### Properties:

- Inherits all from EventEmitter.
- All options.

##### Events:

- __balance(balance)__ - Emitted when balance is updated. `balance` is in
  satoshis (big number).
- __tx(tx)__ - Emitted when a TX is added to the wallet's TXPool.
- __load(ts)__ - Emitted when the TXPool is finished loading. `ts` is the
  timestamp of the last transaction in the pool.
- __error(err)__ - Emitted on error.

##### Methods:

- Inherits all from EventEmitter.
- __addKey(key)__ - Add public key to wallet (multisig).
- __removeKey(key)__ - Remove public key from wallet (multisig).
- __derive(index)__ - Derive a new wallet at `index` (HD-only).
- __getPrivateKey([enc])__ - Return private key as a byte array or whatever
  encoding specified (`base58` or `hex`).
- __getScript()__ - Get the _raw_ redeem script as a byte array.
- __getScriptHash()__ - Return the hash of the redeem script as a byte array.
- __getScriptAddress()__ - Return the address of the scripthash.
- __getPublicKey([enc])__ - Return the public key in desired encoding (byte
  array by default).
- __getKeyHash([enc])__ - Return the hash of the public key.
- __getKeyAddress()__ - Return the address of the public key.
- __getHash([enc])__ - Return scripthash if a `scripthash` wallet, otherwise
  return the public key hash.
- __getAddress()__ - Return the scripthash address if a `scripthash` wallet,
  otherwise return the address of the public key.
- __ownOutput(tx, [index])__ - Check to see if output at `index` pertains to
  this wallet. If `index` is not present, all outputs will be tested.
- __ownInput(tx, [index])__ - Check to see if input at `index` pertains to
  this wallet. If `index` is not present, all inputs will be tested.
- __fillUnspent(tx, [changeAddress], [fee])__ - Fill tx with inputs necessary
  for total output value. Uses `wallet.unspent()` as the unspent list.
- __fillTX(tx)__ - "Fill" a transactions' inputs with references to its
  previous outputs if available.
- __scriptInputs(tx)__ - Compile necessary scripts for inputs (with OP_0 where
  the signatures should be). Will not overwrite existing input scripts.
- __signInputs(tx)__ - Sign all inputs possible in the TX. Finalize input
  scripts if possible.
- __sign(tx)__ - Equivalent to calling both `scriptInputs(tx)` and
  `signInputs(tx)` in one go.
- __addTX(tx)__ - Add a transaction to the wallet's TXPool.
- __all()__ - Returns all transactions from the TXPool.
- __unspent()__ - Returns all TXes with unspent outputs from the TXPool.
- __pending()__ - Returns all TXes in the TXPool that have yet to be included
  in a block.
- __balance()__ - Returns total balance of the TXPool.
- __fill(tx)__ - Attempt to `fillUnspent(tx)`. Return `null` if failed to reach
  total output value. Return `tx` if successful.
- __toAddress()__ - Return blockchain-explorer-like data in the format of:

                    {
                      address: [address],
                      hash160: [hash],
                      received: [total received (big number)],
                      sent: [total sent (big number)]
                      balance: [total balance (big number)],
                      txs: [array of txs]
                    }

- __toJSON([encrypt])__ - Return a serialized wallet in JSON format. `encrypt`
  must be a callback which accepts and encrypts a string if you want the
  private keys to be encrypted when serializing.

##### Static:

- Inherits all from Function.
- __toSecret(priv, [compressed])__ - Convert a private key to a base58
  string. Mimics the bitcoind CBitcoinSecret object for converting private keys
  to and from base58 strings. The same format bitcoind uses for `dumpprivkey`
  and `importprivkey`.
- __fromSecret(priv)__ - Convert a base58 private key string to a
  private key. See above for more information.
- __key2hash(key)__ - Return hash of a public key (byte array).
- __hash2addr(hash, [prefix])__ - Return address of hash. `prefix` can be
  `pubkey`, `pubkeyhash`, `multisig`, or `scripthash`. Only `scripthash`
  actually has a different base58 prefix.
- __addr2hash(address, [prefix])__ - Convert address back to a hash. Do
  checksum verification (returns empty array if checksum fails). If `prefix` is
  null, bcoin will detect the prefix.
- __validateAddress(address, [prefix])__ - Return true if address is a valid
  address for `prefix`. i.e. `bcoin.wallet.validateAddress('3L...',
  'scripthash')`.
- __fromJSON(json, [decrypt])__ - Return a wallet from a serialized JSON
  wallet. `decrypt` must be a callback which can decrypt the private keys
  encrypted by the `encrypt` callback (see `toJSON` above).

#### bcoin.utils

- __toArray(msg, [enc])__ - Converts `msg` to an array. `msg` can be a string
  where `enc` can be null (for converting ascii to a byte array) or `hex`.
- __toBase58(arr)__ - Convert a byte array to base58.
- __fromBase58(msg)__ - Convert a base58 string to a byte array.
- __isBase58(msg)__ - Test `msg` to see if it is a base58 string.
- __ripemd160(data, [enc])__ - RIPEMD160 hash function. Returns byte array.
- __sha1(data, [enc])__ - SHA1 hash function. Returns byte array.
- __ripesha(data, [enc])__ - SHA256+RIPEMD160 hash function. Returns byte array.
- __checksum(data, [enc])__ - Create a checksum using a double SHA256.
- __sha256(data, [enc])__ - SHA256 hash function. Returns byte array.
- __dsha256(data, [enc])__ - Double SHA256 hash function. Returns byte array.
- __writeAscii(dst, str, off)__ - Write an ascii string to a byte array.
  Returns number of bytes written.
- __readAscii(arr, off, len, printable)__ - Read ascii from a byte array. Set
  `printable` to get only printable characters.
- __ascii2array(str)__ - Convert ASCII string to byte array.
- __array2ascii(arr)__ - Convert byte array to ASCII string.
- __array2utf8(arr)__ - Convert byte array to UTF8 string.
- __copy(src, dst, off, [force])__ - Copy data from `src` to `dst` at offset
  `off`. Set `force` to increase `dst` size if necessary.
- __stringify(arr)__ - Convert byte array to ASCII string.
- __toHex(arr)__ - Convert byte array to hex string.
- __binaryInsert(list, item, compare, [search])__ - Do a binary insert on
  `list`. `compare` is a compare callback. Set `search` for just a binary
  search.
- __utils.isEqual(a, b)__ - Compare two byte arrays.
- __utils.nextTick(callback)__ - `process.nextTick` or `setImmediate` if
  available.
- __utils.RequestCache__ - TODO.
- __utils.asyncify(callback)__ - Ensure that a callback executes asynchronously
  by wrapping it in a nextTick.
- __utils.assert()__
- __utils.assert.equal()__
- __utils.btc()__ - Convert satoshis (big number) to BTC string.
- __utils.satoshi()__ - Convert BTC string (must have a decimal point) to
  satoshis (big number).

#### Packet List

TODO

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2014-2016.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[bip37]: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
[escrow]: https://en.bitcoin.it/wiki/Contract#Example_2:_Escrow_and_dispute_mediation
