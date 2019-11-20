/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const eb2k = require('../lib/eb2k');

const vectors = [
  {
    pass: '1234567890',
    salt: '286e37f0b031c0d2c72c674b116e5342',
    keyLen: 16,
    ivLen: 16,
    key: '1fc6b89794d36b3ce33087de2c107fb6',
    iv: '8df8d21d44bfe94ab64cde7d6496857f'
  },
  {
    pass: '1234567890',
    salt: '113bdee3c90ee160997b2e373660368e',
    keyLen: 16,
    ivLen: 16,
    key: '85560be2bd49c607ca036024999c3a30',
    iv: 'daddbffe81ee02330c98d492c8f430bd'
  },
  {
    pass: 'foo',
    salt: '113bdee3c90ee160997b2e373660368e',
    keyLen: 16,
    ivLen: 16,
    key: 'b25272c2fa948e94d01242e297762876',
    iv: '562dedfd27b08b383254ffe1efc7b60d'
  },
  {
    pass: '1234567890',
    salt: 'bdb867fd73611c0586852f406b934243',
    keyLen: 16,
    ivLen: 16,
    key: '85dad080e8a280f6f9ef18808afea519',
    iv: 'a3ada9edf9fb2c4433a6efbbc210505a'
  },
  {
    pass: '1234567890',
    salt: '0eca5c2e3a32fa90e57d685621eb9786',
    keyLen: 16,
    ivLen: 16,
    key: '0a9b842e6bbf13a26a5e99e5ec625857',
    iv: 'c48bd7cfd5803964a8132326692ef6d8'
  },
  {
    pass: 'foo',
    salt: '0eca5c2e3a32fa90e57d685621eb9786',
    keyLen: 16,
    ivLen: 16,
    key: 'df157b6c6d652f934a5fee158c5cc0e7',
    iv: '9e434c07188328c657638b42b9b2040d'
  },
  {
    pass: '1234567890',
    salt: 'f27df2f6f6856e9bb4e2fe4c5269162a',
    keyLen: 16,
    ivLen: 16,
    key: '654a6043e4e021375d0954f3b1a66fb4',
    iv: '361d6661e43465d2ae203380f0a30c74'
  },
  {
    pass: '1234567890',
    salt: 'acf9985e9f755604b48dc03f48c8f584',
    keyLen: 16,
    ivLen: 16,
    key: '7b8b628d62ca33fa5133bed68e5d18b9',
    iv: '218e80364ecac6bf3fee95781baa98e6'
  },
  {
    pass: 'foo',
    salt: 'acf9985e9f755604b48dc03f48c8f584',
    keyLen: 16,
    ivLen: 16,
    key: '040b57f89272efc3e225672799a9d2b7',
    iv: '7b611924696718c6fbfb600965ee587e'
  }
];

describe('EB2K', function() {
  for (const test of vectors) {
    it(`should derive key ${test.key}`, () => {
      const [key, iv] = eb2k.derive(
        Buffer.from(test.pass, 'binary'),
        Buffer.from(test.salt, 'hex'),
        test.keyLen,
        test.ivLen
      );

      assert.strictEqual(key.toString('hex'), test.key);
      assert.strictEqual(iv.toString('hex'), test.iv);
    });
  }
});
