var bcoin = require('bcoin');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var bn = require('bn.js');

function createGenesisBlock(options) {
  var parser = bcoin.protocol.parser;
  var tx, block, txRaw, blockRaw;

  if (!options.flags) {
    options.flags = new Buffer(
      'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
      'ascii');
  }

  if (!options.script) {
    options.script = {
      code: [
        new Buffer('04678afdb0fe5548271967f1a67130b7105cd6a828e039'
          + '09a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c3'
          + '84df7ba0b8d578a4c702b6bf11d5f', 'hex'),
        constants.opcodes.OP_CHECKSIG
      ]
    };
  }

  if (!options.reward)
    options.reward = 50 * constants.COIN;

  tx = {
    version: 1,
    inputs: [{
      prevout: {
        hash: constants.NULL_HASH,
        index: 0xffffffff
      },
      script: {
        code: [
          new bn(486604799).toBuffer('le'),
          new bn(4).toBuffer('le'),
          options.flags
        ]
      },
      sequence: 0xffffffff
    }],
    outputs: [{
      value: options.reward,
      script: options.script
    }],
    locktime: 0
  };

  tx.inputs[0].script.code[1].opcode = 1;

  txRaw = bcoin.protocol.framer.tx(tx);
  tx._raw = txRaw;
  tx._size = txRaw.length;
  tx._witnessSize = 0;

  block = {
    version: options.version,
    prevBlock: constants.NULL_HASH,
    merkleRoot: utils.dsha256(txRaw).toString('hex'),
    ts: options.ts,
    bits: options.bits,
    nonce: options.nonce,
    txs: [tx]
  };

  blockRaw = bcoin.protocol.framer.block(block);

  block = parser.parseBlock(blockRaw);

  block._hash = utils.dsha256(blockRaw.slice(0, 80));
  block.hash = block._hash.toString('hex');
  block._raw = blockRaw;
  block._size = blockRaw.length;
  block._witnessSize = 0;
  block.height = 0;

  tx = block.txs[0];
  tx.height = 0;
  tx.ts = block.ts;
  tx._hash = block.merkleRoot;
  tx.hash = tx._hash.toString('hex');

  return block;
}

var main = createGenesisBlock({
  version: 1,
  ts: 1231006505,
  bits: 486604799,
  nonce: 2083236893
});

var testnet = createGenesisBlock({
  version: 1,
  ts: 1296688602,
  bits: 486604799,
  nonce: 414098458
});

var regtest = createGenesisBlock({
  version: 1,
  ts: 1296688602,
  bits: 545259519,
  nonce: 2
});

var segnet3 = createGenesisBlock({
  version: 1,
  ts: 1452831101,
  bits: 0x1d00ffff,
  nonce: 0
});

var segnet4 = createGenesisBlock({
  version: 1,
  ts: 1452831101,
  bits: utils.toCompact(network.segnet4.pow.limit),
  nonce: 0
});

utils.print(main);
utils.print(testnet);
utils.print(regtest);
utils.print(segnet3);
utils.print('main hash: %s', utils.revHex(main.hash));
utils.print('main raw: %s', main._raw.toString('hex'));
utils.print('');
utils.print('testnet hash: %s', utils.revHex(testnet.hash));
utils.print('testnet raw: %s', testnet._raw.toString('hex'));
utils.print('');
utils.print('regtest hash: %s', utils.revHex(regtest.hash));
utils.print('regtest raw: %s', regtest._raw.toString('hex'));
utils.print('segnet3 hash: %s', utils.revHex(segnet3.hash));
utils.print('segnet3 raw: %s', segnet3._raw.toString('hex'));
utils.print('segnet4 hash: %s', utils.revHex(segnet4.hash));
utils.print('segnet4 raw: %s', segnet4._raw.toString('hex'));
utils.print(segnet4);
