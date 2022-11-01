/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const {BloomFilter} = require('bfilter');
const assert = require('bsert');
const Address = require('../lib/primitives/address');
const Script = require('../lib/script/script');
const MTX = require('../lib/primitives/mtx');
const FullNode = require('../lib/node/fullnode');
const ChainEntry = require('../lib/blockchain/chainentry');
const pkg = require('../lib/pkg');

if (process.browser)
  return;

const ports = {
  p2p: 49331,
  node: 49332
};

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  memory: true,
  workers: true,
  workersSize: 2,
  port: ports.p2p,
  httpPort: ports.node
});

const {NodeClient} = require('../lib/client');

const nclient = new NodeClient({
  port: ports.node,
  apiKey: 'foo',
  timeout: 15000
});

// regtest genesis coinbase address
const addr =
  Address.fromString('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt', 'regtest');
let blocks = null;

describe('Node HTTP', function() {
  this.timeout(15000);

  before(async () => {
    await node.open();
    await nclient.open();
  });

  after(async () => {
    await nclient.close();
    await node.close();
  });

  // m/44'/1'/0'/0/{0,1}
  const pubkeys = [
    Buffer.from('02a7451395735369f2ecdfc829c0f'
      + '774e88ef1303dfe5b2f04dbaab30a535dfdd6', 'hex'),
    Buffer.from('03589ae7c835ce76e23cf8feb32f1a'
      + 'df4a7f2ba0ed2ad70801802b0bcd70e99c1c', 'hex')
  ];

  it('should get info', async () => {
    const info = await nclient.getInfo();
    assert.strictEqual(info.network, node.network.type);
    assert.strictEqual(info.version, pkg.version);
    assert(typeof info.pool === 'object');
    assert.strictEqual(info.pool.agent, node.pool.options.agent);
    assert(typeof info.chain === 'object');
    assert.strictEqual(info.chain.height, 0);
    assert(typeof info.indexes === 'object');
    assert(typeof info.indexes.addr === 'object');
    assert.equal(info.indexes.addr.enabled, false);
    assert.equal(info.indexes.addr.height, 0);
    assert(typeof info.indexes.tx === 'object');
    assert.equal(info.indexes.addr.enabled, false);
    assert.equal(info.indexes.tx.height, 0);
    assert.deepStrictEqual(info.indexes.filter, {});
  });

  it('should execute an rpc call', async () => {
    const info = await nclient.execute('getblockchaininfo', []);
    assert.strictEqual(info.blocks, 0);
  });

  it('should execute an rpc call with bool parameter', async () => {
    const info = await nclient.execute('getrawmempool', [true]);
    assert.deepStrictEqual(info, {});
  });

  it('should get a block template', async () => {
    const json = await nclient.execute('getblocktemplate', [{
      rules: ['segwit']
    }]);
    assert.deepStrictEqual(json, {
      capabilities: ['proposal'],
      mutable: ['time', 'transactions', 'prevblock'],
      version: 536870912,
      rules: ['!segwit'],
      vbavailable: {},
      vbrequired: 0,
      height: 1,
      previousblockhash:
        '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
      target:
        '7fffff0000000000000000000000000000000000000000000000000000000000',
      bits: '207fffff',
      noncerange: '00000000ffffffff',
      curtime: json.curtime,
      mintime: 1296688603,
      maxtime: json.maxtime,
      expires: json.expires,
      sigoplimit: 80000,
      sizelimit: 4000000,
      weightlimit: 4000000,
      longpollid:
        '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
        + '00000000',
      submitold: false,
      coinbaseaux: { flags: '6d696e65642062792062636f696e' },
      coinbasevalue: 5000000000,
      transactions: [],
      default_witness_commitment:
        '6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48beb'
        + 'd836974e8cf9'
    });
  });

  it('should send a block template proposal', async () => {
    const attempt = await node.miner.createBlock();
    const block = attempt.toBlock();
    const hex = block.toRaw().toString('hex');
    const json = await nclient.execute('getblocktemplate', [{
      mode: 'proposal',
      data: hex
    }]);
    assert.strictEqual(json, null);
  });

  it('should validate a legacy address', async () => {
    const json = await nclient.execute('validateaddress', [
      addr.toString(node.network)
    ]);
    assert.deepStrictEqual(json, {
      isvalid: true,
      address: addr.toString(node.network),
      scriptPubKey: Script.fromAddress(addr).toRaw().toString('hex'),
      iswitness: false,
      isscript: false
    });
  });

  it('should not validate invalid address', async () => {
    // Valid Mainnet P2WPKH from
    // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    const json = await nclient.execute('validateaddress', [
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    ]);

    // Sending an address from the incorrect network
    // should result in an invalid address
    assert.deepStrictEqual(json, {
      isvalid: false
    });
  });

  it('should validate a p2wpkh address', async () => {
    const address = 'bcrt1q8gk5z3dy7zv9ywe7synlrk58elz4hrnegvpv6m';
    const addr = Address.fromString(address);
    const script = Script.fromAddress(addr);

    const json = await nclient.execute('validateaddress', [
      address
    ]);

    assert.deepStrictEqual(json, {
      isvalid: true,
      iswitness: true,
      address: address,
      isscript: addr.isScripthash(),
      scriptPubKey: script.toJSON(),
      witness_version: addr.version,
      witness_program: addr.hash.toString('hex')
    });
  });

  it('should validate a p2sh address', async () => {
    const script = Script.fromMultisig(2, 2, pubkeys);
    const address = Address.fromScript(script);

    // Test the valid case - render the address to the
    // correct network
    {
      const json = await nclient.execute('validateaddress', [
        address.toString(node.network)
      ]);

      assert.deepEqual(json, {
        isvalid: true,
        address: address.toString(node.network),
        scriptPubKey: Script.fromAddress(address).toJSON(),
        isscript: true,
        iswitness: false
      });
    }

    // Test the invalid case - render the address to the
    // incorrect network, making it an invalid address
    {
      const json = await nclient.execute('validateaddress', [
        address.toString('main')
      ]);

      assert.deepEqual(json, {
        isvalid: false
      });
    }
  });

  it('should validate a p2wsh address', async () => {
    const script = Script.fromMultisig(2, 2, pubkeys);
    const scriptPubKey = script.forWitness();
    const program = script.sha256();
    const address = Address.fromProgram(0, program);

    const json = await nclient.execute('validateaddress', [
      address.toString(node.network)
    ]);

    assert.deepEqual(json, {
      isvalid: true,
      address: address.toString(node.network),
      scriptPubKey: scriptPubKey.toJSON(),
      isscript: true,
      iswitness: true,
      witness_version: 0,
      witness_program: program.toString('hex')
    });
  });

  it('should generate 10 blocks from RPC call', async () => {
    blocks = await nclient.execute(
      'generatetoaddress',
      [10, addr.toString('regtest')]
    );
    assert.strictEqual(blocks.length, 10);
  });

  // Depends on the previous test to generate blocks.
  it('should fetch block header by height', async () => {
    // fetch corresponding header and block
    const height = 7;
    const header = await nclient.getBlockHeader(height);
    assert.equal(header.height, height);

    const properties = [
      'hash', 'version', 'prevBlock',
      'merkleRoot', 'time', 'bits',
      'nonce', 'height', 'chainwork'
    ];

    for (const property of properties)
      assert(property in header);

    const block = await nclient.getBlock(height);

    assert.equal(block.hash, header.hash);
    assert.equal(block.height, header.height);
    assert.equal(block.version, header.version);
    assert.equal(block.prevBlock, header.prevBlock);
    assert.equal(block.merkleRoot, header.merkleRoot);
    assert.equal(block.time, header.time);
    assert.equal(block.bits, header.bits);
    assert.equal(block.nonce, header.nonce);
  });

  it('should fetch block header by hash', async () => {
    const info = await nclient.getInfo();

    const headerByHash = await nclient.getBlockHeader(info.chain.tip);
    const headerByHeight = await nclient.getBlockHeader(info.chain.height);

    assert.deepEqual(headerByHash, headerByHeight);
  });

  it('should fetch null for block header that does not exist', async () => {
    // Many blocks in the future.
    const header = await nclient.getBlockHeader(40000);
    assert.equal(header, null);
  });

  it('should have valid header chain', async () => {
    // Starting at the genesis block.
    let prevBlock = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < 10; i++) {
      const header = await nclient.getBlockHeader(i);

      assert.equal(prevBlock, header.prevBlock);
      prevBlock = header.hash;
    }
  });

  it('should initiate rescan from socket without a bloom filter', async () => {
    // Rescan from height 5. Without a filter loaded = no response, but no error
    const response = await nclient.call('rescan', 5);
    assert.strictEqual(null, response);
  });

  it('should initiate rescan from socket WITH a bloom filter', async () => {
    // Create an SPV-standard Bloom filter and add one of our wallet addresses
    const filter = BloomFilter.fromRate(20000, 0.001, BloomFilter.flags.ALL);
    filter.add(addr.getHash());

    // Send Bloom filter to server
    await nclient.call('set filter', filter.toRaw());

    // `rescan` commands the node server to check blocks against a bloom filter.
    // When the server matches a transaction in a block to the filter, it
    // sends a socket call BACK to the client with the ChainEntry of the block,
    // and an array of matched transactions. Because of this callback, the
    // CLIENT MUST have a `block rescan` hook in place or the server will throw.
    const matchingBlocks = [];
    nclient.hook('block rescan', (entry, txs) => {
      // Coinbase transactions were mined to our watch address, matching filter.
      assert.strictEqual(txs.length, 1);
      const cbtx = MTX.fromRaw(txs[0]);
      assert.strictEqual(
        cbtx.outputs[0].getAddress().toString('regtest'),
        addr.toString('regtest')
      );

      // Blocks are returned as raw ChainEntry
      matchingBlocks.push(
        ChainEntry.fromRaw(entry).rhash().toString('hex')
      );
    });

    // Rescan from height 5 -- should return blocks 5 through 10, inclusive.
    await nclient.call('rescan', 5);
    assert.deepStrictEqual(matchingBlocks, blocks.slice(4));
  });
});
