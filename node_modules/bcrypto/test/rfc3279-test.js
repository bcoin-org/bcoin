/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('fs');
const rfc3279 = require('../lib/encoding/rfc3279');

const DSA_PARAMS = Path.resolve(__dirname, 'data', 'dsa-parameters.pem');

const dsaParamsPem = fs.readFileSync(DSA_PARAMS, 'utf8');
const dsaParamsJson = require('./data/dsa-parameters.json');

describe('RFC3279', function() {
  it('should deserialize DSA parameters', () => {
    const key = rfc3279.DSAParams.fromPEM(dsaParamsPem);
    const json = dsaParamsJson;

    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.g.value.toString('hex'), json.g);

    assert.strictEqual(key.toPEM(), dsaParamsPem);
  });
});
