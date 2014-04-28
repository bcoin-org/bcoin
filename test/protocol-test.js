var assert = require('assert');
var bcoin = require('../');

describe('Protocol', function() {
  var parser;
  var framer;
  beforeEach(function() {
    parser = bcoin.protocol.parser();
    framer = bcoin.protocol.framer();
  });

  it('should encode/decode version packet', function(cb) {
    var ver = framer.version();
    parser.once('packet', function(packet) {
      assert.equal(packet.cmd, 'version');
      assert.equal(packet.payload.v, 70002);
      assert.equal(packet.payload.relay, false);

      cb();
    });
    parser.execute(ver);
  });
});
