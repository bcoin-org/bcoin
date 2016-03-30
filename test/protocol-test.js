var assert = require('assert');
var bcoin = require('../');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;

describe('Protocol', function() {
  var version = require('../package.json').version;
  var agent = '/bcoin:' + version + '/';

  var parser;
  var framer;
  beforeEach(function() {
    parser = bcoin.protocol.parser();
    framer = bcoin.protocol.framer();
  });

  function packetTest(command, payload, test) {
    it('should encode/decode ' + command, function(cb) {
      var ver = new Buffer(framer[command](payload));
      parser.once('packet', function(packet) {
        assert.equal(packet.cmd, command);
        test(packet.payload);
        cb();
      });
      parser.feed(ver);
    });
  }

  packetTest('version', {}, function(payload) {
    assert.equal(payload.version, constants.version);
    assert.equal(payload.agent, agent);
    assert.equal(payload.height, 0);
    assert.equal(payload.relay, false);
  });

  packetTest('version', { relay: true, height: 10 }, function(payload) {
    assert.equal(payload.version, constants.version);
    assert.equal(payload.agent, agent);
    assert.equal(payload.height, 10);
    assert.equal(payload.relay, true);
  });

  packetTest('verack', {}, function(payload) {
  });

  var peers = [
    {
      ipv6: '0000:0000:0000:0000:0000:ffff:0000:0000',
      ipv4: '0.0.0.0',
      port: 8333,
      ts: Date.now() / 1000 | 0
    },
    {
      ipv6:  '0000:0000:0000:0000:0000:ffff:7f00:0001',
      ipv4: '127.0.0.1',
      port: 18333,
      ts: Date.now() / 1000 | 0
    }
  ];

  // Convert peers to framer payload format, backup strings.
  peers.forEach(function(addr) {
    addr._ipv4 = addr.ipv4;
    addr.ipv4 = addr.ipv4.split('.').map(function(n) {
      return +n;
    });
    addr._ipv6 = addr.ipv6;
    addr.ipv6 = new Buffer(addr.ipv6.replace(/:/g, ''), 'hex');
    addr.services = constants.localServices;
  });

  packetTest('addr', peers, function(payload) {
    assert.equal(typeof payload.length, 'number');
    assert.equal(payload.length, 2);

    assert.equal(typeof payload[0].ts, 'number');
    assert.equal(payload[0].services, constants.localServices);
    assert.equal(payload[0].ipv6, peers[0]._ipv6);
    assert.equal(payload[0].ipv4, peers[0]._ipv4);
    assert.equal(payload[0].port, peers[0].port);

    assert.equal(typeof payload[1].ts, 'number');
    assert.equal(payload[1].services, constants.localServices);
    assert.equal(payload[1].ipv6, peers[1]._ipv6);
    assert.equal(payload[1].ipv4, peers[1]._ipv4);
    assert.equal(payload[1].port, peers[1].port);
  });

  it('should include the raw data of only one transaction in a ' +
     'parsed transaction', function() {
    var rawTwoTxs = new Buffer(
      '0100000004b124cca7e9686375380c845d0fd002ed704aef4472f4cc193' +
      'fca4aa1b3404da400000000b400493046022100d3c9ba786488323c975f' +
      'e61593df6a8041c5442736f361887abfe5c97175c72b022100ca61688f4' +
      '72f4c01ede05ffc50426d68db375f72937b5f39d67835b191b6402f014c' +
      '67514104c4bee5e6dbb5c1651437cb4386c1515c7776c64535077204c6f' +
      '24f05a37d04a32bc78beb2193b53b104c9954c44b0ce168bc78efd5f1e1' +
      'c7db9d6c21b301659921027f10c31cb2ad7e0388cf5187924f1294082ba' +
      '5d4c697bbca7fd83a6af61db7d552aeffffffffb124cca7e9686375380c' +
      '845d0fd002ed704aef4472f4cc193fca4aa1b3404da401000000fd15010' +
      '0483045022100a35b7fc1973a0a8962c240a7336b501e149ef167491081' +
      'e8df91dc761f4e96c2022004ee4d20983a1d0fb96e9bedf86de03b66d7b' +
      'c50595295b1fb3b5fd2740df3c9014cc9514104c4bee5e6dbb5c1651437' +
      'cb4386c1515c7776c64535077204c6f24f05a37d04a32bc78beb2193b53' +
      'b104c9954c44b0ce168bc78efd5f1e1c7db9d6c21b3016599410495b62d' +
      '1e76a915e5ed3694298c5017d2818d22acbf2a8bd9fa4cf635184e15247' +
      'dc7e1a48beb82c1fdddc3b84ac58cec12c8f8b9ca83341ac90299c697fc' +
      '94cb4104e3394f3eea40b7abe32f4ad376a80f5a213287d1361b5580e3f' +
      'e70d13a5db0666e2593283b6b5abc01d98cfff5679d8c36b7caefa1c4df' +
      '81b10bc45c3812de5f53aeffffffffb124cca7e9686375380c845d0fd00' +
      '2ed704aef4472f4cc193fca4aa1b3404da402000000fd5e010047304402' +
      '20606d6187e0ade69192f4a447794cdabb8ea9a4e70df09aa8bc689242c' +
      '7ffeded02204165ec8edfc9de19d8a94e5f487c8a030187ae16a11e575a' +
      '955f532a81b631ad01493046022100f7764763d17757ffdeda3d66cfaa6' +
      'ad3b8f759ddc95e8f73858dba872762658a0221009e903d526595ff9d6d' +
      '53835889d816de4c47d78371d7a13223f47602b34bc71e014cc9524104c' +
      '4bee5e6dbb5c1651437cb4386c1515c7776c64535077204c6f24f05a37d' +
      '04a32bc78beb2193b53b104c9954c44b0ce168bc78efd5f1e1c7db9d6c2' +
      '1b3016599410495b62d1e76a915e5ed3694298c5017d2818d22acbf2a8b' +
      'd9fa4cf635184e15247dc7e1a48beb82c1fdddc3b84ac58cec12c8f8b9c' +
      'a83341ac90299c697fc94cb4104e3394f3eea40b7abe32f4ad376a80f5a' +
      '213287d1361b5580e3fe70d13a5db0666e2593283b6b5abc01d98cfff56' +
      '79d8c36b7caefa1c4df81b10bc45c3812de5f53aeffffffffb124cca7e9' +
      '686375380c845d0fd002ed704aef4472f4cc193fca4aa1b3404da404000' +
      '0008a473044022075c0666d413fc85cca94ea2f24adc0fedb61a3ba0fcf' +
      'b240c1a4fd2587b03bf90220525ad4d92c6bf635f8b97c188ebf491c6e3' +
      '42b767a5432f318cbb0245a7f64be014104c4bee5e6dbb5c1651437cb43' +
      '86c1515c7776c64535077204c6f24f05a37d04a32bc78beb2193b53b104' +
      'c9954c44b0ce168bc78efd5f1e1c7db9d6c21b3016599ffffffff01a029' +
      'de5c0500000017a9141d9ca71efa36d814424ea6ca1437e67287aebe348' +
      '70000000001000000019457e669dc6b344c0090d10eb22a0377022898d4' +
      '607fbdf1e3cef2a323c13fa900000000b2004730440220440d67386a27d' +
      '6776e102b82ce2d583e23d51f8ac3bb94749bd10c03ce71410e022041b4' +
      '6c5d46b14ef72af9d96fb814fa894077d534a4de1215363ee68fb8d4f50' +
      '1014c67514104c4bee5e6dbb5c1651437cb4386c1515c7776c645350772' +
      '04c6f24f05a37d04a32bc78beb2193b53b104c9954c44b0ce168bc78efd' +
      '5f1e1c7db9d6c21b301659921027f10c31cb2ad7e0388cf5187924f1294' +
      '082ba5d4c697bbca7fd83a6af61db7d552aeffffffff0250c3000000000' +
      '0001976a9146167aeaeec59836b22447b8af2c5e61fb4f1b7b088ac00a3' +
      'dc5c0500000017a9149eb21980dc9d413d8eac27314938b9da920ee53e8' +
      '700000000', 'hex');
    var rawFirstTx = new Buffer(
      '0100000004b124cca7e9686375380c845d0fd002ed704aef4472f4cc193' +
      'fca4aa1b3404da400000000b400493046022100d3c9ba786488323c975f' +
      'e61593df6a8041c5442736f361887abfe5c97175c72b022100ca61688f4' +
      '72f4c01ede05ffc50426d68db375f72937b5f39d67835b191b6402f014c' +
      '67514104c4bee5e6dbb5c1651437cb4386c1515c7776c64535077204c6f' +
      '24f05a37d04a32bc78beb2193b53b104c9954c44b0ce168bc78efd5f1e1' +
      'c7db9d6c21b301659921027f10c31cb2ad7e0388cf5187924f1294082ba' +
      '5d4c697bbca7fd83a6af61db7d552aeffffffffb124cca7e9686375380c' +
      '845d0fd002ed704aef4472f4cc193fca4aa1b3404da401000000fd15010' +
      '0483045022100a35b7fc1973a0a8962c240a7336b501e149ef167491081' +
      'e8df91dc761f4e96c2022004ee4d20983a1d0fb96e9bedf86de03b66d7b' +
      'c50595295b1fb3b5fd2740df3c9014cc9514104c4bee5e6dbb5c1651437' +
      'cb4386c1515c7776c64535077204c6f24f05a37d04a32bc78beb2193b53' +
      'b104c9954c44b0ce168bc78efd5f1e1c7db9d6c21b3016599410495b62d' +
      '1e76a915e5ed3694298c5017d2818d22acbf2a8bd9fa4cf635184e15247' +
      'dc7e1a48beb82c1fdddc3b84ac58cec12c8f8b9ca83341ac90299c697fc' +
      '94cb4104e3394f3eea40b7abe32f4ad376a80f5a213287d1361b5580e3f' +
      'e70d13a5db0666e2593283b6b5abc01d98cfff5679d8c36b7caefa1c4df' +
      '81b10bc45c3812de5f53aeffffffffb124cca7e9686375380c845d0fd00' +
      '2ed704aef4472f4cc193fca4aa1b3404da402000000fd5e010047304402' +
      '20606d6187e0ade69192f4a447794cdabb8ea9a4e70df09aa8bc689242c' +
      '7ffeded02204165ec8edfc9de19d8a94e5f487c8a030187ae16a11e575a' +
      '955f532a81b631ad01493046022100f7764763d17757ffdeda3d66cfaa6' +
      'ad3b8f759ddc95e8f73858dba872762658a0221009e903d526595ff9d6d' +
      '53835889d816de4c47d78371d7a13223f47602b34bc71e014cc9524104c' +
      '4bee5e6dbb5c1651437cb4386c1515c7776c64535077204c6f24f05a37d' +
      '04a32bc78beb2193b53b104c9954c44b0ce168bc78efd5f1e1c7db9d6c2' +
      '1b3016599410495b62d1e76a915e5ed3694298c5017d2818d22acbf2a8b' +
      'd9fa4cf635184e15247dc7e1a48beb82c1fdddc3b84ac58cec12c8f8b9c' +
      'a83341ac90299c697fc94cb4104e3394f3eea40b7abe32f4ad376a80f5a' +
      '213287d1361b5580e3fe70d13a5db0666e2593283b6b5abc01d98cfff56' +
      '79d8c36b7caefa1c4df81b10bc45c3812de5f53aeffffffffb124cca7e9' +
      '686375380c845d0fd002ed704aef4472f4cc193fca4aa1b3404da404000' +
      '0008a473044022075c0666d413fc85cca94ea2f24adc0fedb61a3ba0fcf' +
      'b240c1a4fd2587b03bf90220525ad4d92c6bf635f8b97c188ebf491c6e3' +
      '42b767a5432f318cbb0245a7f64be014104c4bee5e6dbb5c1651437cb43' +
      '86c1515c7776c64535077204c6f24f05a37d04a32bc78beb2193b53b104' +
      'c9954c44b0ce168bc78efd5f1e1c7db9d6c21b3016599ffffffff01a029' +
      'de5c0500000017a9141d9ca71efa36d814424ea6ca1437e67287aebe348' +
      '700000000', 'hex');
    var tx = bcoin.protocol.parser.parseTX(rawTwoTxs);
    assert.deepEqual(bcoin.protocol.framer.tx(tx), rawFirstTx);
  });
});
