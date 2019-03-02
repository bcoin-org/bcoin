/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const KeyRing = require('../lib/primitives/keyring');
const Script = require('../lib/script/script');
const Opcode = require('../lib/script/opcode');

const uncompressed = KeyRing.fromSecret(
  '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', 'main');

const compressed = KeyRing.fromSecret(
  'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1', 'main');

describe('KeyRing', function() {
  it('should get uncompressed public key', () => {
    assert.strictEqual(
      '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b'
      + '8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235',
      uncompressed.getPublicKey('hex'));
  });

  it('should get uncompressed public key address', () => {
    assert.strictEqual(
      '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN',
      uncompressed.getKeyAddress('base58', 'main'));
  });

  it('should get uncompressed WIF', () => {
    assert.strictEqual(
      '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss',
      uncompressed.toSecret('main'));
  });

  it('should get compressed public key', () => {
    assert.strictEqual(
      '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
      compressed.getPublicKey('hex'));
  });

  it('should get compressed public key address', () => {
    assert.strictEqual(
      '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV',
      compressed.getKeyAddress('base58', 'main'));
  });

  it('should get compressed WIF', () => {
    assert.strictEqual(
      'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
      compressed.toSecret('main'));
  });

  it('should get keys from multisig', () => {
    const script = Script.fromMultisig(1, 2, [
      compressed.getPublicKey(),
      uncompressed.getPublicKey()]);

    assert.strictEqual(
      compressed.getPublicKey(),
      KeyRing.fromMultisigScript(script, 1).getPublicKey());
    assert.strictEqual(
      uncompressed.getPublicKey(),
      KeyRing.fromMultisigScript(script, 2).getPublicKey());
  });

  describe('Witness KeyRing', function() {
    before(() => {
      uncompressed.witness = true;
      compressed.witness = true;
    });

    after(() => {
      uncompressed.witness = false;
      compressed.witness = false;
    });

    it('should get program from uncompressed public key', () => {
      const op = Buffer.from(
        'b5bd079c4d57cc7fc28ecf8213a6b791625b8183', 'hex');
      const script = Script.fromOptions({
        raw: Buffer.concat([Buffer.from('0014', 'hex'), op]),
        code: [
          new Opcode(0, null),
          new Opcode(20, op)
        ]
      });

      assert.deepStrictEqual(script,
        uncompressed.getProgram());
    });

    it('should get program from script from uncompressed public key', () => {
      const keyring = KeyRing.fromOptions({
        witness: true,
        key: uncompressed.privateKey,
        script: Script.fromPubkey(uncompressed.publicKey)
      });

      const op = Buffer.from(
        '000676452ca2b203855a8f56af1a6297bff43c'
        + '356072e85de974231aa3d3457e', 'hex');
      const script = Script.fromOptions({
        raw: Buffer.concat([Buffer.from('0020', 'hex'), op]),
        code: [
          new Opcode(0, null),
          new Opcode(32, op)
        ]
      });

      assert.deepStrictEqual(script, keyring.getProgram());
    });

    it('should get program from compressed public key', () => {
      const op = Buffer.from(
        '9a1c78a507689f6f54b847ad1cef1e614ee23f1e', 'hex');
      const script = Script.fromOptions({
        raw: Buffer.concat([Buffer.from('0014', 'hex'), op]),
        code: [
          new Opcode(0, null),
          new Opcode(20, op)
        ]
      });

      assert.deepStrictEqual(script,
        compressed.getProgram());
    });

    it('should get program from script from compressed public key', () => {
      const keyring = KeyRing.fromOptions({
        witness: true,
        key: compressed.privateKey,
        script: Script.fromPubkey(compressed.publicKey)
      });

      const op = Buffer.from(
        '2e271faa2325c199d25d22e1ead982e45b64ee'
        + 'b4f31e73dbdf41bd4b5fec23fa', 'hex');
      const script = Script.fromOptions({
        raw: Buffer.concat([Buffer.from('0020', 'hex'), op]),
        code: [
          new Opcode(0, null),
          new Opcode(32, op)
        ]
      });

      assert.deepStrictEqual(script, keyring.getProgram());
    });
  });
});
