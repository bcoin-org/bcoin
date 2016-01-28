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

## Creating and sending a transaction

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

## Multisig Transactions

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
- __abbr()__ - Return a binary array of serialized headers.
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

#### Static:

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
- __locatorHashes(hash/height)__ - Return array of block locator hashes
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

#### Static:

- __reward(height)__ - Calculate block reward based on a height.
- __fromJSON(json)__ - Return `Block` object from serialized JSON block format.

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

##### Events:

- None.

##### Methods:

- Inherits all from Object.
- None.

#### Static:

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

#### Static:

- Inherits all from Object.
- __fromJSON(json)__ - Return ChainBlock from serialized JSON format.
- __fromRaw(data)__ - Return ChainBlock from ChainDB binary format.

#### HDSeed (from Object)

Generate an HDSeed (potentially from a passed-in mnemonic) for HD key
generation.

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

#### Static:

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

#### Static:

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

#### Static:

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

#### Static:

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

#### Static:

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
- __loadHeaders(hashes, stop)__ - Send `getheaders`.
- __loadBlocks(hashes, stop)__ - Send `getblocks`.

#### Static:

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
  on value (__NOTE:__ setting this to `true` for a `getblocks` sync is a very
  bad idea).
- __relay__ - Relay value in `version` packet. See BIP-37 for details.
- __createSocket(port, host)__ - Callback to create a socket. Must return a
  node-like socket.
- __seeds__ - List of initial seeds (array of strings in the format of
  `{ipv4/host}:{port}` or `[{ipv6}]:port`). Port will be set to the default
  network port if not present.
- __size__ - Size of pool i.e. the number of peers to maintain connections
  with.
- __parallel__ - Amount of block requests to allow in parallel (default: 2000).
- __redundancy__ - Amount of redundant block requests to make to peers.
  Anything over 1 adds a redundant request. (default: 1).
- __backoffDelta__ - Delta used to calculate the next `backoff` time before
  connecting to a new block peer after one has been destroyed (default: 500).
- __backoffMax__ - Max backoff time that can be calculated (default: 5000).
- __loadTimeout__ - The amount of time (ms) before killing the loader peer if
  an `inv` or `block` packet has not been received (default: 30000).
- __loadInterval__ - The amount of time (ms) before attempting stall recovery
  on the loader peer (which sends another `getblocks`/`getheaders`) (default:
  5000).
- __loadWindow__ - The amount of time to delay before scheduling `getdata`
  requests (default: 250).
- __rangeWindow__ - Disabled.
- __lwm__ - Low watermark queue-length boundary to hit before more
  `getheaders`/`getblocks` requests are attempted (default: 4000).
- __hwm__ - High watermark queue-length boundary to cross before bcoin will
  prevent any further `getheaders`/`getblocks` requests and wait until the low
  watermark has been hit (default: 16000).
- __maxRetries__ - amount of times to retry scheduled requests on peer before
  destroying the peer (default: 42).
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
- __search([id], range)__ - Search a timestamp range, watch for `id` (SPV-only).
- __getBlock(hash, callback)__ - Request block from peer.
- __sendBlock(block)__ - Broadcast a block.
- __getTX(txid, callback)__ - Attempt to search for a particular transaction
  (SPV-only).
- __sendTX(tx)__ - Broadcast a transaction.
- __broadcast(block/tx)__ - Broadcast block or TX.
- __destroy()__ - Destroy pool and peers.
- __getPeer(host)__ - Get peer by host/ip+port.
- __addSeed(host)__ - Add a seed to the seed list.
- __removeSeed(host)__ - Remove a seed from the seed list.
- __misbehaving(peer, dos)__ - Increase peer's banscore by `dos`.
- __isMisbehaving(peer/host)__ - Whether peer is known for misbehaving.

#### Static:

- Inherits all from Function.


#### script

A collection of functions for script handling.

Usage:

- `s = bcoin.script.decode(rawScript)`
- `rawScript = bcoin.script.encode(s)`

##### Functions:

- __decode(s)__ - Decode a raw script into bcoin's deserialized format (an
  array of strings and arrays).
- __encode(s)__ - Encode a deserialized script to a raw binary array.
- __normalize(s)__ - Normalize a script by changing `0` into `[]`, `-1` into
  `'1negate'`, etc. Currently unused.
- __verify(input, output, tx, index, flags)__ - Execute input and previous
  output script and verify input. `index` is the index of the input being
  verified. `flags` is an object with boolean values. Keys can be of any of
  bitcoind's script flags in lowercase. i.e. `minimaldata`, `cleanstack`, etc.
- __subscript(s, lastSep)__ - Return script from `lastSep` with codeseparators
  removed.
- __checksig(msg, sig, key)__ - Verify a signature against a hash and key.
- __sign(msg, key, type)__ - Create a bitcoin ecdsa signature from `msg` and a
  private key. Appends `type` to the signature (the sighash type).
- __execute(s, stack, tx, index, flags)__ - Execute a script. `stack` must be
  an array.
- __bool(value)__ - Cast a binary array to bool. Mimics bitcoind's
  `CastToBool()` function. Checks for negative zero.
- __num(value, useNum, minimaldata)__ - Create a standard little-endian big
  number from `value`. Checks for `minimaldata` if true. Checks for negative
  zero, etc.  Mimics bitcoind's CScriptNum.
- __array(value)__ - Convert big number to script little endian byte array.
- __createMultisig(keys, m, n)__ - Compile a standard multisig script from
  array of keys and `m` and `n` value.
- __createScripthash(s)__ - Compile a scripthash script from `s`.
- __redeem(s)__ - Grab an deserialize redeem script from input script.
- __standard(s)__ - Return standard output script type. `null` if unknown.
- __size(s)__ - Return script size in bytes.
- __isLocktime(s)__ - Returns true if script is a checklocktimeverify script.
- __lockTime(s)__ - Return locktime value pushed onto the stack if
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
- __standardInput(s)__ - Same as `script.standard()`, but works on input
  scripts.
- __isPubkeyInput(s)__ - Returns true if script is pay-to-pubkey input script.
- __isPubkeyhashInput(s)__ - Returns true if script is pay-to-pubkeyhash input
  script.
- __isMultisigInput(s)__ - Returns true if script is multisig input script.
- __isScripthashInput(s)__ - Returns true if script is pay-to-scripthash input
  script.
- __coinbase(s)__ - Extract as much data as possible from a coinbase script
  including `height`, `extraNonce`, `flags`, and `text`.
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
- __pushOnly(s)__ - Returns true if script contains only push opcodes.
- __sigops(s, [accurate])__ - Count number of sigops in script. Legacy counting
  by default. Set `accurate` to true for accurate counting.
- __sigopsScripthash(s)__ - Count sigops in scripthash input + redeem script.
- __args(s)__ - Return number of expected "input args" for output script type.

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

#### Static:

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
  redeemed.
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
- __isFinal(height, ts)__ - Mimics the bitcoind `IsFinalTx()` function. Checks
  the locktime and input sequences. Returns true or false.
- __sigops([scripthash], [accurate])__ - Count sigops in transaction. Set
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

#### Static:

- Inherits all from Function.
- __fromJSON(json)__ - Return TX from serialized JSON format.
- __fromRaw(data)__ - Return TX from standard bitcoin binary format.

#### Wallet (from EventEmitter)

Wallet object.

Usage: `bcoin.wallet(options)`

##### Options:

- TODO

##### Properties:

- Inherits all from EventEmitter.
- All options.
- TODO

##### Events:

- TODO

##### Methods:

- Inherits all from EventEmitter.
- TODO

#### Static:

- Inherits all from Function.

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
