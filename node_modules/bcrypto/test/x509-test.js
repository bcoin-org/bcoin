/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const x509 = require('../lib/encoding/x509');
const pem = require('../lib/encoding/pem');

const file = Path.resolve(__dirname, 'data', 'certs.pem');
const data = fs.readFileSync(file, 'utf8');

function clear(crt) {
  crt.raw = null;
  crt.tbsCertificate.raw = null;
  crt.tbsCertificate.subjectPublicKeyInfo.raw = null;
}

describe('X509', function() {
  let i = 0;
  for (const block of pem.decode(data)) {
    it(`should deserialize and reserialize certificate (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const raw1 = crt1.encode();
      const crt2 = x509.Certificate.decode(raw1);
      const raw2 = crt2.encode();

      clear(crt1);
      clear(crt2);

      assert.deepStrictEqual(crt1, crt2);
      assert.bufferEqual(raw1, raw2);
    });
  }
});
