var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');

describe('TX', function() {
  var parser = bcoin.protocol.parser();

  it('should decode/encode with parser/framer', function() {
    var raw = '010000000125393c67cd4f581456dd0805fa8e9db3abdf90dbe1d4b53e28' +
              '6490f35d22b6f2010000006b483045022100f4fa5ced20d2dbd2f905809d' +
              '79ebe34e03496ef2a48a04d0a9a1db436a211dd202203243d086398feb4a' +
              'c21b3b79884079036cd5f3707ba153b383eabefa656512dd0121022ebabe' +
              'fede28804b331608d8ef11e1d65b5a920720db8a644f046d156b3a73c0ff' +
              'ffffff0254150000000000001976a9140740345f114e1a1f37ac1cc442b4' +
              '32b91628237e88ace7d27b00000000001976a91495ad422bb5911c2c9fe6' +
              'ce4f82a13c85f03d9b2e88ac00000000';
    var tx = bcoin.tx(parser.parseTx(bcoin.utils.toArray(raw, 'hex')));
    assert.equal(bcoin.utils.toHex(tx.render()), raw);
  });
});
