var assert = require('assert');
var bcoin = require('../');

describe('Wallet', function() {
  it('should generate new key and address', function() {
    var w = bcoin.wallet();
    var addr = w.getAddress();
    assert(addr);
    assert(bcoin.wallet.validateAddress(addr));
  });

  it('should validate existing address', function() {
    assert(bcoin.wallet.validateAddress('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert(!bcoin.wallet.validateAddress('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc'));
  });
});
