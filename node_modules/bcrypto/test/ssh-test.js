'use strict';

const assert = require('bsert');
const fs = require('fs');
const path = require('path');
const dsa = require('../lib/dsa');
const rsa = require('../lib/rsa');
const p256 = require('../lib/p256');
const ed25519 = require('../lib/ed25519');
const ssh = require('../lib/ssh');
const {resolve, basename} = path;
const {SSHPublicKey, SSHPrivateKey} = ssh;

const pubs = [
  resolve(__dirname, 'data', 'id_dsa.pub'),
  resolve(__dirname, 'data', 'id_rsa.pub'),
  resolve(__dirname, 'data', 'id_ecdsa.pub'),
  resolve(__dirname, 'data', 'id_dsa_modern.pub'),
  resolve(__dirname, 'data', 'id_dsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_rsa_modern.pub'),
  resolve(__dirname, 'data', 'id_rsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_ecdsa_modern.pub'),
  resolve(__dirname, 'data', 'id_ecdsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_ed25519.pub'),
  resolve(__dirname, 'data', 'id_ed25519_unenc.pub')
];

const privs = [
  resolve(__dirname, 'data', 'id_dsa'),
  resolve(__dirname, 'data', 'id_rsa'),
  resolve(__dirname, 'data', 'id_ecdsa'),
  resolve(__dirname, 'data', 'id_dsa_modern'),
  resolve(__dirname, 'data', 'id_dsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_rsa_modern'),
  resolve(__dirname, 'data', 'id_rsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_ecdsa_modern'),
  resolve(__dirname, 'data', 'id_ecdsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_ed25519'),
  resolve(__dirname, 'data', 'id_ed25519_unenc')
];

const PASSPHRASE = '1234567890';

describe('SSH', function() {
  this.timeout(60000);

  for (const file of pubs) {
    const str = fs.readFileSync(file, 'utf8');

    it(`should reserialize public keys (${basename(file)})`, () => {
      const key1 = SSHPublicKey.fromString(str);
      const str1 = key1.toString();
      const key2 = SSHPublicKey.fromString(str1);
      const str2 = key2.toString();

      switch (key1.type) {
        case 'ssh-dss': {
          const {p, q, g, y} = key1;
          const key = dsa.publicKeyImport({ p, q, g, y });
          assert(dsa.publicKeyVerify(key));
          break;
        }

        case 'ssh-rsa': {
          const {n, e} = key1;
          const key = rsa.publicKeyImport({ n, e });
          assert(rsa.publicKeyVerify(key));
          break;
        }

        case 'ecdsa-sha2-nistp256': {
          assert(p256.publicKeyVerify(key1.point));
          break;
        }

        case 'ssh-ed25519': {
          assert(ed25519.publicKeyVerify(key1.point));
          break;
        }

        default: {
          assert(false);
          break;
        }
      }

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);
      assert.strictEqual(key2.toString(), str.trim());
    });
  }

  for (const file of privs) {
    const str = fs.readFileSync(file, 'utf8');

    let passphrase = PASSPHRASE;

    if (file.includes('modern'))
      passphrase = 'foo';

    it(`should reserialize private keys (${basename(file)})`, () => {
      const key1 = SSHPrivateKey.fromString(str, passphrase);
      const str1 = key1.toString();
      const key2 = SSHPrivateKey.fromString(str1);
      const str2 = key2.toString();

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);

      switch (key1.type) {
        case 'ssh-dss': {
          const {p, q, g, y, x} = key1;
          const key = dsa.privateKeyImport({ p, q, g, y, x });
          assert(dsa.privateKeyVerify(key));
          break;
        }

        case 'ssh-rsa': {
          const {n, e, d, p, q, dp, dq, qi} = key1;
          const key = rsa.privateKeyImport({ n, e, d, p, q, dp, dq, qi });
          assert(rsa.privateKeyVerify(key));
          break;
        }

        case 'ecdsa-sha2-nistp256': {
          assert(p256.privateKeyVerify(key1.key));
          break;
        }

        case 'ssh-ed25519': {
          assert(ed25519.privateKeyVerify(key1.key));
          break;
        }

        default: {
          assert(false);
          break;
        }
      }

      const str3 = key2.toString(passphrase);
      const key3 = SSHPrivateKey.fromString(str3, passphrase);

      let err;
      try {
        SSHPrivateKey.fromString(str3, 'bar');
      } catch (e) {
        err = e;
      }

      assert(err);
      assert(err.message.indexOf('Decryption failed')
        || err.message.indexOf('bad decrypt'));

      assert(key3.toString());
    });
  }
});
