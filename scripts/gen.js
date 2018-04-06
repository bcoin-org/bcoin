'use strict';

const consensus = require('../lib/protocol/consensus');
const TX = require('../lib/primitives/tx');
const Block = require('../lib/primitives/block');
const Script = require('../lib/script/script');

function createGenesisBlock(options) {
  let flags = options.flags;
  let key = options.key;
  let reward = options.reward;

  if (!flags) {
    flags = Buffer.from(
      'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
      'ascii');
  }

  if (!key) {
    key = Buffer.from(''
      + '04678afdb0fe5548271967f1a67130b7105cd6a828e039'
      + '09a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c3'
      + '84df7ba0b8d578a4c702b6bf11d5f', 'hex');
  }

  if (!reward)
    reward = 50 * consensus.COIN;

  const tx = new TX({
    version: 1,
    inputs: [{
      prevout: {
        hash: consensus.NULL_HASH,
        index: 0xffffffff
      },
      script: Script()
        .pushInt(486604799)
        .pushPush(Buffer.from([4]))
        .pushData(flags)
        .compile(),
      sequence: 0xffffffff
    }],
    outputs: [{
      value: reward,
      script: Script.fromPubkey(key)
    }],
    locktime: 0
  });

  const block = new Block({
    version: options.version,
    prevBlock: consensus.NULL_HASH,
    merkleRoot: tx.hash('hex'),
    time: options.time,
    bits: options.bits,
    nonce: options.nonce,
    height: 0
  });

  block.txs.push(tx);

  return block;
}

const main = createGenesisBlock({
  version: 1,
  time: 1231006505,
  bits: 486604799,
  nonce: 2083236893
});

const testnet = createGenesisBlock({
  version: 1,
  time: 1296688602,
  bits: 486604799,
  nonce: 414098458
});

const regtest = createGenesisBlock({
  version: 1,
  time: 1296688602,
  bits: 545259519,
  nonce: 2
});

const segnet3 = createGenesisBlock({
  version: 1,
  time: 1452831101,
  bits: 486604799,
  nonce: 0
});

const segnet4 = createGenesisBlock({
  version: 1,
  time: 1452831101,
  bits: 503447551,
  nonce: 0
});

const btcd = createGenesisBlock({
  version: 1,
  time: 1401292357,
  bits: 545259519,
  nonce: 2
});

console.log(main);
console.log('');
console.log(testnet);
console.log('');
console.log(regtest);
console.log('');
console.log(segnet3);
console.log('');
console.log(segnet4);
console.log('');
console.log('');
console.log('main hash: %s', main.rhash());
console.log('main raw: %s', main.toRaw().toString('hex'));
console.log('');
console.log('testnet hash: %s', testnet.rhash());
console.log('testnet raw: %s', testnet.toRaw().toString('hex'));
console.log('');
console.log('regtest hash: %s', regtest.rhash());
console.log('regtest raw: %s', regtest.toRaw().toString('hex'));
console.log('');
console.log('segnet3 hash: %s', segnet3.rhash());
console.log('segnet3 raw: %s', segnet3.toRaw().toString('hex'));
console.log('');
console.log('segnet4 hash: %s', segnet4.rhash());
console.log('segnet4 raw: %s', segnet4.toRaw().toString('hex'));
console.log('');
console.log('btcd simnet hash: %s', btcd.rhash());
console.log('btcd simnet raw: %s', btcd.toRaw().toString('hex'));
