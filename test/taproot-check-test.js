/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const { taprootTreeHelper } = require('../lib/script/taproot');
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

describe('Helper Functions', () => {
  it('taprootTreeHelper should produce tree root', () => {
    const b = new Script({ raw: Buffer.from('b') });
    const c = new Script({ raw: Buffer.from('c') });
    const d = new Script({ raw: Buffer.from('d') });
    const f = new Script({ raw: Buffer.from('f') });
    const g = new Script({ raw: Buffer.from('g') });

    assert(Buffer.compare(taprootTreeHelper([]), Buffer.from([])) === 0, 'empty');
    assert(Buffer.compare(taprootTreeHelper([{ script: b }]), Buffer.from([0xc1, 0xb5, 0xbd, 0x5a, 0xf8, 0x73, 0xb3, 0xcf, 0x6e, 0x5a, 0x90, 0xed, 0x7d, 0xfa, 0x3, 0xda, 0x9, 0xad, 0x4c, 0x4f, 0x61, 0xae, 0xdb, 0x43, 0x57, 0xc8, 0x7f, 0x13, 0x24, 0x4d, 0xd, 0x44])) === 0, '1 leaf');
    assert(Buffer.compare(taprootTreeHelper([{ script: b, version: 194 }]), Buffer.from([0x6, 0xab, 0xb1, 0xa7, 0xf7, 0x4b, 0xbb, 0x10, 0x30, 0xc8, 0x38, 0x5a, 0x75, 0x73, 0x52, 0xd4, 0xbd, 0xe3, 0x67, 0x43, 0xc4, 0xba, 0x1e, 0xab, 0x73, 0x4c, 0x9b, 0x84, 0x41, 0xe1, 0xb, 0x93])) === 0, 'diff version');
    assert(Buffer.compare(taprootTreeHelper([{ script: c }]), Buffer.from([0x99, 0x3e, 0x66, 0xf0, 0xdc, 0x53, 0x60, 0x73, 0xd5, 0xa2, 0xc5, 0x98, 0x92, 0x67, 0xbc, 0x87, 0x62, 0x4, 0x53, 0x3, 0xb9, 0x1c, 0x2, 0x7b, 0xf3, 0x36, 0x66, 0x56, 0x5a, 0x85, 0xf2, 0x70])) === 0, 'diff code');
    assert(Buffer.compare(taprootTreeHelper([[[[[{ script: b }]]]]]), Buffer.from([0xc1, 0xb5, 0xbd, 0x5a, 0xf8, 0x73, 0xb3, 0xcf, 0x6e, 0x5a, 0x90, 0xed, 0x7d, 0xfa, 0x3, 0xda, 0x9, 0xad, 0x4c, 0x4f, 0x61, 0xae, 0xdb, 0x43, 0x57, 0xc8, 0x7f, 0x13, 0x24, 0x4d, 0xd, 0x44])) === 0, 'deep leaf');
    assert(Buffer.compare(taprootTreeHelper([{ script: b }, { script: b }]), Buffer.from([0x12, 0x99, 0x1d, 0x5d, 0x42, 0x73, 0x5f, 0x67, 0x9b, 0xb1, 0xa2, 0x4a, 0x40, 0x26, 0xf4, 0xa6, 0xe4, 0xfb, 0xe4, 0x96, 0x12, 0xe2, 0xb9, 0x44, 0xf2, 0x6a, 0xb9, 0x31, 0x98, 0x25, 0x39, 0x12])) === 0, '2 same leaves');
    assert(Buffer.compare(taprootTreeHelper([{ script: b }, { script: c }]), Buffer.from([0x53, 0x14, 0x98, 0x4f, 0x24, 0xab, 0x8, 0x11, 0x3d, 0x57, 0x90, 0x63, 0x6c, 0x6c, 0x7f, 0xb8, 0xa0, 0x3, 0xe6, 0xb, 0x50, 0xe5, 0xb6, 0x0, 0xb6, 0x2e, 0x97, 0xd0, 0x41, 0x33, 0xe4, 0xa5])) === 0, '2 diff leaves');
    assert(Buffer.compare(taprootTreeHelper([{ script: b }, [{ script: c }], { script: d }, [{ script: f }, { script: g }]]), Buffer.from([0x7d, 0x6, 0x22, 0x7e, 0xc4, 0xd4, 0xdc, 0x84, 0xec, 0x46, 0xa6, 0x24, 0x81, 0xf8, 0x6c, 0xea, 0x34, 0x66, 0xd2, 0x47, 0x91, 0x84, 0xe5, 0xdc, 0x17, 0x14, 0x59, 0x76, 0xbf, 0x36, 0x1a, 0xef])) === 0, 'multiple levels');
  });
});
