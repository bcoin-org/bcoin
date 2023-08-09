'use strict';

const assert = require('bsert');
const MTX = require('../lib/primitives/mtx');
const Path = require('../lib/wallet/path');

const mtx1json = require('./data/mtx1.json');
const mtx1 = MTX.fromJSON(mtx1json);

describe('MTX', function() {
  it('should serialize path', () => {
    const input = mtx1.inputs[0];
    const view = mtx1.view;
    const path = view.getPathFor(input);

    {
      const got = path.getJSON();
      const want = {
        name: 'default',
        account: 0,
        change: false,
        derivation: 'm/0\'/0/0'
      };

      assert.deepStrictEqual(got, want);
    }

    {
      const got = path.getJSON('regtest');
      const want = {
        name: 'default',
        account: 0,
        change: false,
        derivation: 'm/44\'/1\'/0\'/0/0'
      };

      assert.deepStrictEqual(got, want);
    }
  });

  it('should deserialize path', () => {
    const path1 = Path.fromJSON({
      name: 'default',
      account: 0,
      change: true,
      derivation: 'm/0\'/1/1'
    });

    const path2 = new Path().fromJSON({
      name: 'default',
      account: 0,
      change: true,
      derivation: 'm/44\'/1\'/0\'/1/1'
    });

    assert.deepStrictEqual(path1, path2);

    const got = path1;
    const want = new Path();
    want.name = 'default';
    want.account = 0;
    want.branch = 1;
    want.index = 1;

    assert.deepStrictEqual(got, want);
  });
});
