/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Network = require('../lib/protocol/network');
const TXMeta = require('../lib/primitives/txmeta');

const network = Network.get('regtest');

describe('TXMeta', function() {
  it('should return JSON for txmeta', async () => {
    // unconfirmed at height 100
    const txmeta1 = new TXMeta();
    const txJSON1 = txmeta1.getJSON(network, null, 100);
    assert.strictEqual(txJSON1.confirmations, 0);

    // confirmed once at height 100
    const txmeta2 = TXMeta.fromOptions( {height: 100} );
    txmeta2.height = 100;
    const txJSON2 = txmeta2.getJSON(network, null, 100);
    assert.strictEqual(txJSON2.confirmations, 1);
  });
});
