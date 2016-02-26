var bcoin = require('bcoin');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var bn = bcoin.bn;

function createGenesisBlock(options) {
  var parser = bcoin.protocol.parser;
  var tx, block;

  if (!options.flags) {
    options.flags = new Buffer(
      'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
      'ascii');
  }

  if (!options.script) {
    options.script = [
      new Buffer('04678afdb0fe5548271967f1a67130b7105cd6a828e039'
        + '09a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c3'
        + '84df7ba0b8d578a4c702b6bf11d5f', 'hex'),
      'checksig'
    ];
  }

  if (!options.reward)
    options.reward = new bn(50).mul(constants.coin);

  tx = {
    version: 1,
    inputs: [{
      prevout: {
        hash: utils.toHex(constants.zeroHash),
        index: 0xffffffff
      },
      script: [
        new bn(486604799, 'le').toBuffer(),
        new bn(4, 'le').toBuffer(),
        options.flags
      ],
      sequence: 0xffffffff
    }],
    outputs: [{
      value: options.reward,
      script: options.script
    }],
    locktime: 0
  };

  tx._raw = bcoin.protocol.framer.tx(tx);

  block = {
    version: options.version,
    prevBlock: utils.toHex(constants.zeroHash),
    merkleRoot: utils.toHex(utils.dsha256(tx._raw)),
    ts: options.ts,
    bits: options.bits,
    nonce: options.nonce,
    txs: [tx]
  };

  block._raw = bcoin.protocol.framer.block(block);

  block = parser.parseBlock(block._raw);

  block._hash = utils.dsha256(block._raw.slice(0, 80));
  block.hash = utils.toHex(block._hash);
  block.network = true;
  block.height = 0;

  tx = block.txs[0];
  tx.network = true;
  tx.height = 0;
  tx.ts = block.ts;
  tx._hash = block.merkleRoot;
  tx.hash = utils.toHex(tx._hash);

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

var segnet = createGenesisBlock({
  version: 1,
  ts: 1452368293,
  bits: 0x1d00ffff,
  nonce: 0
});

utils.print(main);
utils.print(testnet);
utils.print(regtest);
utils.print(segnet);
utils.print('main hash: %s', main.hash);
utils.print('main raw: %s', utils.toHex(main._raw));
utils.print('');
utils.print('testnet hash: %s', testnet.hash);
utils.print('testnet raw: %s', utils.toHex(testnet._raw));
utils.print('');
utils.print('regtest hash: %s', regtest.hash);
utils.print('regtest raw: %s', utils.toHex(regtest._raw));
utils.print('segnet hash: %s', segnet.hash);
utils.print('segnet raw: %s', utils.toHex(segnet._raw));
