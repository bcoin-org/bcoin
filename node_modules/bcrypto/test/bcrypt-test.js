/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const bcrypt = require('../lib/bcrypt');

const test = {
  pass: '1234567890',
  salt: 'edf2ee939723f10f09cca07c90b31c47',
  rounds: 16,
  size: 48,
  key: '8476c2efc085d68616acf2809661839427346028dfc98ae0e82'
    + '584c72fdfbc337920678fdb35c7296de17dfeb4f988f5'
};

describe('Bcrypt', function() {
  this.timeout(10000);

  it('should derive key', () => {
    const key = bcrypt.pbkdf(
      Buffer.from(test.pass, 'binary'),
      Buffer.from(test.salt, 'hex'),
      test.rounds,
      test.size
    );

    assert.strictEqual(key.toString('hex'), test.key);
  });
});
