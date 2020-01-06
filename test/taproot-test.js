
/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const BufferReader = require('bufio').BufferReader;
const CoinView = require('../lib/coins/coinview');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const {TaggedHash} = require('../lib/utils/taggedhash');
const Script = require('../lib/script/script');
const {digests, types, flags} = Script;
const common = require('./util/common');
const schnorr = require('bcrypto/lib/schnorr');

// Test data from https://github.com/pinheadmz/bitcoin/tree/taproottest-0.21.1
const taprootTXs = require('./data/taproot_test_vectors.json');

function* getTests(success = true) {
  for (const test of taprootTXs) {
    const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

    // Produce test cases where all inputs are consensus-valid
    // (some may still be non-standard)
    const inputs = [];
    for (let i = 0; i < test.inputs.length; i++) {
      const input = test.inputs[i].success;
      input.comment = test.inputs[i].comment;
      input.standard = test.inputs[i].standard;
      inputs.push(input);
      tx.inputs[i].script = Script.fromJSON(input.scriptSig);
      tx.inputs[i].witness.fromString(input.witness);
    }

    yield {tx, inputs, prevouts: test.prevouts, mandatory: true};

    // ALSO produce test cases where one input is invalid and the rest are valid
    if (!success) {
      for (let fail = 0; fail < test.inputs.length; fail++) {
        if (!test.inputs[fail].fail)
          continue;

        const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));
        const inputs = [];
        for (let i = 0; i < test.inputs.length; i++) {
          const input = i === fail ?
              test.inputs[i].fail
            : test.inputs[i].success;
          input.comment = test.inputs[i].comment;
          input.standard = test.inputs[i].standard;
          inputs.push(input);
          tx.inputs[i].script = Script.fromJSON(input.scriptSig);
          tx.inputs[i].witness.fromString(input.witness);
        }

        yield {tx, inputs, prevouts: test.prevouts, mandatory: false};
      }
    }
  }
}

describe('Taproot', function() {
  it('should create a generic tagged hash', () => {
    // Without 'bytes' argument
    const testHash1 = new TaggedHash('test');
    const digest1 = testHash1.digest(Buffer.alloc(32, 12));

    // With 'bytes' argument
    const testHash2 = new TaggedHash('test', Buffer.alloc(32, 12));
    assert.bufferEqual(digest1, testHash2);

    // Test vector created with
    // https://github.com/bitcoin/bitcoin/blob/0.21/
    //   test/functional/test_framework/key.py#L17-L21
    // TaggedHash('test', bytearray([12]*32)).hex()
    assert.bufferEqual(
      digest1,
      Buffer.from(
        'f88d26c35028f6e63b5cfc3fc67b4a3ae6da9c48d9f0be94df97a94ab64d5a68',
        'hex'
      )
    );
  });

  describe('Get Annex', () => {
    it('should not find annex in pre-taproot TXs', () => {
      // None of the legacy or SegWit TXs in ./data are Taproot-spenders
      for (let i = 1; i < 11; i++) {
        const txContext = common.readTX(`tx${i}`);
        const [tx] = txContext.getTX();
        for (const input of tx.inputs) {
          const witness = input.witness;
          assert.strictEqual(witness.getAnnex(), null);
        }
      }
    });

    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        it(test.inputs[i].comment, () => {
          const expected = test.inputs[i].annex;
          const actual = test.tx.inputs[i].witness.getAnnex();

          if (expected === null)
            assert.strictEqual(actual, null);
          else
            assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Get Spend Type', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const spendtype = test.tx.inputs[i].witness.getSpendType();

          if (test.inputs[i].annex != null)
            assert(spendtype & (1 << 0));

          if (test.inputs[i].annex == null)
            assert(~spendtype & (1 << 0));

          if (test.inputs[i].script != null)
            assert(spendtype & (1 << 1));

          if (test.inputs[i].script == null)
            assert(~spendtype & (1 << 1));
        });
      }
    }
  });

  describe('Get Tapleaf', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const actual = test.tx.inputs[i].witness.getTapleaf();
          const expected = test.inputs[i].script;

          if (test.inputs[i].script == null)
            assert(actual == null);
          else
            assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Get Control Block', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const actual = test.tx.inputs[i].witness.getControlBlock();

          if (test.inputs[i].script == null)
            assert(!actual);
          else
            assert(actual);
        });
      }
    }
  });

  describe('Compute BIP341/BIP342 Sighash', () => {
    for (const test of getTests()) {
      const tx = test.tx;

      // Collect all inputs to this TX
      const coins = [];
      for (let i = 0; i < tx.inputs.length; i++) {
        const key = tx.inputs[i].prevout.toKey();
        const coin = Coin.fromKey(key);
        const utxo = new BufferReader(
          Buffer.from(test.prevouts[i], 'hex')
        );
        coin.value = utxo.readI64();
        coin.script.fromRaw(utxo.readVarBytes());

        coins.push(coin);
      }

      // Test the sighash of each input
      for (let i = 0; i < tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        // Skip test cases with "unknown" 33-byte public keys.
        // These sighashes are randomly bitflipped in the Bitcoin Core
        // test to ensure they are actually NOT checked.
        if (test.inputs[i].comment.match(/oldpk/g))
          continue;

        // The top witness stack item is the signature
        const sig = tx.inputs[i].witness.items[0];

        // In Taproot, SIGHASH_ALL is default.
        // A 65-byte signature indicates a custom sighash type.
        // Some test vectors include signatures of other lengths.
        // These are mostly invalid, but can be accepted in some
        // edge cases such as OP_SUCCESSx. Skip them for this test.
        let type = 0;
        if (sig.length === 65)
          type = sig[sig.length - 1];
        else if (sig.length !== 64)
          continue;

        it(test.inputs[i].comment, () => {
          let codeseppos = 0xffffffff;
          if (test.inputs[i].codeseppos >= 0)
            codeseppos = test.inputs[i].codeseppos;

          const coin = coins[i];
          const actual = tx.signatureHash(
            i,
            coin.script,
            coin.value,
            type,
            digests.TAPROOT,
            coins,
            codeseppos
          );

          const expected = Buffer.from(test.inputs[i].sighash, 'hex');

          assert.bufferEqual(expected, actual, null, test.inputs[i].comment);
        });
      }
    }
  });

  describe('Verify signature (schnorr)', function() {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        // Some test vectors wrap witness V1 program in P2SH.
        // This is NOT taproot, and is therefore "anyone can spend".
        // These unencumbered spends are valid, but non-standard.
        // Skip for this test.
        if (    test.inputs[i].comment.match(/applic/g)
            && !test.inputs[i].standard)
          continue;

        // Skip test case with no signature
        if (test.inputs[i].comment.match(/cleanstack/g))
          continue;

        // Skip script spends for now
        if (test.inputs[i].script)
          continue;

        // Skip test case with no signature
        if (test.inputs[i].comment.match(/cleanstack/g))
          continue;

        // Skip script spends for now
        if (test.inputs[i].script)
          continue;

        it(`${test.inputs[i].comment}`, () => {
          const sighash = Buffer.from(test.inputs[i].sighash, 'hex');
          const sig = test.tx.inputs[i].witness.items[0];

          // Get pubkey from prevout scriptPubKey (witness program)
          const utxo = test.prevouts[i];
          // Skip 8 byte value and 1 byte scriptPubkey length byte (in hex)
          const script = Script.fromJSON(utxo.slice(18));
          const program = script.getProgram();
          const pubkey = program.data;

          assert(schnorr.verify(sighash, sig.slice(0, 64), pubkey));
        });
      }
    }
  });

  describe('Verify Taproot commitment', function() {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        // Only test Tapscript spends
        if (!test.inputs[i].script)
          continue;

        // Skip P2SH-nested witness V1 (not Taproot)
        // Skip nested V1
        if (   test.inputs[i].comment.match(/applic/g)
            && !test.inputs[i].standard)
          continue;

        it(`${test.inputs[i].comment}`, () => {
          // Get pubkey from prevout scriptPubKey (witness program)
          const utxo = test.prevouts[i];
          // Skip 8 byte value and 1 byte scriptPubkey length byte (in hex)
          const script = Script.fromJSON(utxo.slice(18));
          const witness = test.tx.inputs[i].witness;
          assert(Script.verifyTaprootCommitment(witness, script));
        });
      }
    }
  });

  describe('Identify pay-to-taproot programs', function() {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        it(`${test.inputs[i].comment}`, () => {
          // Get pubkey from prevout scriptPubKey (witness program)
          const utxo = test.prevouts[i];
          // Skip 8 byte value and 1 byte scriptPubkey length byte (in hex)
          const script = Script.fromJSON(utxo.slice(18));

          // Skip nested V1
          if (test.inputs[i].comment.match(/applic/g)) {
            if (test.inputs[i].standard)
              assert.strictEqual(script.getType(), types.TAPROOT);
            else
              assert.notStrictEqual(script.getType(), types.TAPROOT);
          } else {
            if (test.inputs[i].mode === 'taproot')
              assert.strictEqual(script.getType(), types.TAPROOT);

            if (test.inputs[i].mode !== 'taproot')
              assert.notStrictEqual(script.getType(), types.TAPROOT);
          }
        });
      }
    }
  });

  describe('Verify Taproot transactions', function() {
    // Flags for mempool inclusion
    const standardFlags = flags.STANDARD_VERIFY_FLAGS;

    // Flags for block inclusion after Taproot activation,
    // inlcuding all previous deployments.
    const mandatoryFlags = flags.MANDATORY_VERIFY_FLAGS
      | flags.VERIFY_P2SH
      | flags.VERIFY_DERSIG
      | flags.VERIFY_CHECKLOCKTIMEVERIFY
      | flags.VERIFY_CHECKSEQUENCEVERIFY
      | flags.VERIFY_WITNESS
      | flags.VERIFY_NULLDUMMY
      | flags.VERIFY_TAPROOT;

    TXS: for (const test of getTests(false)) {
      const tx = test.tx;

      // Expected block inclusion verification result
      const mandatory = test.mandatory;

      // Expected mempool inclusion verification result
      let standard = true;

      // Generate test name and set standardness flag
      let name = '';
      for (let i = 0; i < tx.inputs.length; i++) {
        // Skip script spends for now
        if (test.inputs[i].script)
          continue TXS;

        name +=  ' ' + test.inputs[i].comment;
        if (!test.inputs[i].standard)
          standard = false;
      }

      // Add coins for each input
      const view = new CoinView();
      for (let i = 0; i < tx.inputs.length; i++) {
        const key = tx.inputs[i].prevout.toKey();
        const coin = Coin.fromKey(key);
        const utxo = new BufferReader(
          Buffer.from(test.prevouts[i], 'hex')
        );
        coin.value = utxo.readI64();
        coin.script.fromRaw(utxo.readVarBytes());

        view.addCoin(coin);
      }

      it(`should ${mandatory ? '' : 'not '}pass mandatory:${name}`, () => {
        // Verify mandatoryness (block)
        assert.strictEqual(mandatory, tx.verify(view, mandatoryFlags));
      });

      // Invalid TXs can't be standard, no reason to test.
      if (!mandatory)
        continue;

      it(`should ${standard ? '' : 'not '}pass standard:${name}`, () => {
        // Verify standardness (mempool)
        const isStandard =
          tx.verify(view, standardFlags)
          && tx.hasStandardInputs(view)
          && tx.hasStandardWitness(view);
        assert.strictEqual(standard, isStandard);

        if (tx.version >= 1 && tx.version <= 2)
          assert(tx.checkStandard()[0], tx.checkStandard()[1]);
      });
    };
  });
});
