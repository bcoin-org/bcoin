/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const schnorr = require('bcrypto/lib/schnorr');
const random = require('bcrypto/lib/random');
const {taggedHash} = require('../lib/utils');
const consensus = require('../lib/protocol/consensus');
const opcodes = Script.opcodes;

// Create a BIP340 Schnorr keypair
const priv = schnorr.privateKeyGenerate();
const pub = schnorr.publicKeyCreate(priv);

// Error Messages
const ERR_EMPTY_WITNESS = { message: 'WITNESS_PROGRAM_WITNESS_EMPTY'};
const ERR_SIG_SCHNORR = { message: 'TAPROOT_INVALID_SIG' };
const ERR_CONTROLBLOCK_SIZE = { message: 'TAPROOT_WRONG_CONTROL_SIZE' };
const ERR_WITNESS_PROGRAM_MISMATCH = { message: 'WITNESS_PROGRAM_MISMATCH' };
const ERR_STACK_SIZE = { message: /STACK_SIZE/g };
const ERR_SIG_SCHNORR_SIZE = {message: 'SCHNORR_SIG_SIZE' };

describe('Taproot Check', function() {
  describe('Key spend', function() {
    // Create a pay-to-taproot key-spend UTXO
    const keyspendUTXO = new Coin();
    keyspendUTXO.hash = random.randomBytes(32);
    keyspendUTXO.index = 0;
    keyspendUTXO.script = Script.fromProgram(1, pub);
    keyspendUTXO.value = 1e8;

    // Sign 1-in 1-out taproot key-spend MTX
    function signMTX(mtx) {
      const hash = mtx.signatureHashTaproot(
        0,                    // input index
        keyspendUTXO.value,   // input value
        0,                    // SIGHASH_ALL
        [keyspendUTXO],       // coins
        0xffffffff,           // codeseparator position
      );
      const sig = schnorr.sign(hash, priv);
      mtx.inputs[0].witness.items[0] = sig;
    }

    it('should have valid signature', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);
      assert(mtx.verify());
    });

    it('should have empty signature', () => {
      const mtx = new MTX();
      mtx.addCoin(keyspendUTXO);

      // No witness to sign transaction
      assert.throws(
        () => mtx.check(),
        ERR_EMPTY_WITNESS
      );
    });

    it('should have invalid schnorr signature size', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({ value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);

      mtx.inputs[0].witness.items[0] = mtx.inputs[0].witness.items[0].slice(0, -1);

      assert.throws(
        () => mtx.check(),
        ERR_SIG_SCHNORR_SIZE
      );
    });

    it('should have invalid signature', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);

      // Malleate signature by flipping a bit
      mtx.inputs[0].witness.items[0][0] ^= 0x01;

      assert.throws(
        () => mtx.check(),
        ERR_SIG_SCHNORR
      );
    });
  });

  describe('Script spend', function() {
    // Simple script that requires no signing
    const script = Script.fromString('OP_1');
    const tapLeaf = Buffer.from([
        0xc0,   // leaf version
        0x01,   // script size
        0x51    // OP_1
    ]);

    // Construct tapscript tree (with only one leaf)
    const k0 = taggedHash.TapLeafHash.digest(tapLeaf);
    const tapTweak = Buffer.alloc(64);
    pub.copy(tapTweak, 0);
    k0.copy(tapTweak, 32);
    const t = taggedHash.TapTweakHash.digest(tapTweak);
    const [tweaked, odd] = schnorr.publicKeyTweakSum(pub, t);

    // Construct control block from 1-leaf tree
    const controlBlock = Buffer.alloc(33);
    controlBlock[0] = 0xc0 + (odd ? 1 : 0);
    pub.copy(controlBlock, 1);

    // Create a pay-to-taproot script-spend UTXO
    const scriptspendUTXO = new Coin();
    scriptspendUTXO.hash = random.randomBytes(32);
    scriptspendUTXO.index = 0;
    scriptspendUTXO.script = Script.fromProgram(1, tweaked);
    scriptspendUTXO.value = 1e8;

    it('should have valid tapscript', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);

      mtx.check();
      assert(mtx.verify());
      assert(mtx.hasStandardWitness(mtx.view));
    });

    it('should be non-standard with annex', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);
      mtx.inputs[0].witness.push(Buffer.from([0x50])); // annex

      mtx.check();
      assert(mtx.verify());
      assert(!mtx.hasStandardWitness(mtx.view));
    });

    it('should have invalid control block', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      // Content of invalid control block doesn't matter
      const invalid = Buffer.alloc(controlBlock.length + 1);
      mtx.inputs[0].witness.push(invalid);

      assert.throws(
        () => mtx.check(),
        ERR_CONTROLBLOCK_SIZE
      );
    });

    it('should not match witness program', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      const script = Script.fromString('OP_2');

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);

      assert.throws(
        () => mtx.check(),
        ERR_WITNESS_PROGRAM_MISMATCH
      );
    });

    for (const NUM of [999, 1000]) {
      it(`should have ${NUM === 1000 ? 'invalid' : 'valid' } tapscript with ${NUM} signatures`, () => {
        const script = new Script();
        for (let i = 0; i < NUM; i++) {
          script.pushData(pub);
          script.pushOp(opcodes.OP_CHECKSIGVERIFY);
        }
        script.pushOp(opcodes.OP_1);
        script.compile();
        const raw = script.toRaw();

        const scriptSize = script.getVarSize();
        let tapLeaf = bio.write(scriptSize + 1);
        tapLeaf.writeU8(0xc0); // leaf version
        tapLeaf.writeVarBytes(raw);
        tapLeaf = tapLeaf.render();

        // Construct tapscript tree (with only one leaf)
        const k0 = taggedHash.TapLeafHash.digest(tapLeaf);
        const tapTweak = Buffer.alloc(64);
        pub.copy(tapTweak, 0);
        k0.copy(tapTweak, 32);
        const t = taggedHash.TapTweakHash.digest(tapTweak);
        const [tweaked, odd] = schnorr.publicKeyTweakSum(pub, t);

        // Construct control block from 1-leaf tree
        const controlBlock = Buffer.alloc(33);
        controlBlock[0] = 0xc0 + (odd ? 1 : 0);
        pub.copy(controlBlock, 1);

        // Create money for us to spend with this tapscript
        const utxo = new Coin();
        utxo.hash = random.randomBytes(32);
        utxo.index = 0;
        utxo.script = Script.fromProgram(1, tweaked);
        utxo.value = 1e8;

        // Spend the UTXO with our tapscript in a new TX
        const mtx = new MTX();
        mtx.outputs.push(new Output({value: 1e8 - 10000 }));
        mtx.addCoin(utxo);

        for (let i = 0; i < NUM; i++) {
          mtx.inputs[0].witness.push(Buffer.alloc(0));
        }

        mtx.inputs[0].witness.push(script.toRaw());
        mtx.inputs[0].witness.push(controlBlock);

        const hash = mtx.signatureHashTaproot(
          utxo.index,           // input index
          utxo.value,           // input value
          0,                    // SIGHASH_ALL
          [utxo],               // coins
          0xffffffff,           // codeseparator position
        );
        const sig = schnorr.sign(hash, priv);

        for (let i = 0; i < NUM; i++) {
          mtx.inputs[0].witness.items[i] = sig;
        }

        if (NUM >= consensus.MAX_SCRIPT_STACK) {
          assert.throws(
            () => mtx.check(),
            ERR_STACK_SIZE
          );
        } else {
          // Max script size does not apply to taproot
          assert(raw.length > consensus.MAX_SCRIPT_SIZE);

          mtx.check();
          assert(mtx.verify());
        }
      });
    }
  });
});
