'use strict';

const Script = require('../lib/script/script');
const Stack = require('../lib/script/stack');
const Witness = require('../lib/script/witness');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const TX = require('../lib/primitives/tx');
const random = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const flags = Script.flags;

let consensus = null;

try {
  consensus = require('nodeconsensus');
} catch (e) {
  ;
}

if (consensus)
  console.log('Running against bitcoinconsensus...');

const MANDATORY = flags.MANDATORY_VERIFY_FLAGS | flags.VERIFY_WITNESS;
const STANDARD = flags.STANDARD_VERIFY_FLAGS;

function verifyConsensus(tx, index, output, value, flags) {
  if (!consensus)
    return 'OK';
  return consensus.verify(tx.toRaw(), index, output.toRaw(), value, flags);
}

function assertConsensus(tx, output, flags, code) {
  if (!consensus)
    return;

  const err = verifyConsensus(tx, 0, output, 0, flags);

  if (err !== code) {
    console.log('bitcoinconsensus mismatch!');
    console.log(`${err} (bitcoin core) !== ${code} (bcoin)`);
    console.log(tx);
    console.log(output);
    console.log(flags);
    console.log('TX: %s', tx.toRaw().toString('hex'));
    console.log('Output Script: %s', output.toRaw().toString('hex'));
  }
}

function randomSignature() {
  const r = secp256k1.generatePrivateKey();
  const s = secp256k1.generatePrivateKey();
  return secp256k1.toDER(Buffer.concat([r, s]));
}

function randomKey() {
  const x = secp256k1.generatePrivateKey();
  const y = secp256k1.generatePrivateKey();

  if (rand(0, 2) === 0) {
    const p = Buffer.from([2 | (y[y.length - 1] & 1)]);
    return Buffer.concat([p, x]);
  }

  const p = Buffer.from([4]);
  return Buffer.concat([p, x, y]);
}

function randomOutpoint() {
  const hash = random.randomBytes(32).toString('hex');
  return new Outpoint(hash, rand(0, 0xffffffff));
}

function randomInput() {
  const input = Input.fromOutpoint(randomOutpoint());

  if (rand(0, 5) === 0)
    input.sequence = rand(0, 0xffffffff);

  return input;
}

function randomOutput() {
  return Output.fromScript(randomScript(), rand(0, 1e8));
}

function randomTX() {
  const tx = new TX();
  const inputs = rand(1, 5);
  const outputs = rand(0, 5);

  tx.version = rand(0, 0xffffffff);

  for (let i = 0; i < inputs; i++)
    tx.inputs.push(randomInput());

  for (let i = 0; i < outputs; i++)
    tx.outputs.push(randomOutput());

  if (rand(0, 5) === 0)
    tx.locktime = rand(0, 0xffffffff);

  tx.refresh();

  return tx;
}

function randomWitness(redeem) {
  const size = rand(1, 100);
  const witness = new Witness();

  for (let i = 0; i < size; i++) {
    const len = rand(0, 100);
    witness.push(random.randomBytes(len));
  }

  if (redeem)
    witness.push(redeem);

  witness.compile();

  return witness;
}

function randomInputScript(redeem) {
  const size = rand(1, 100);
  const script = new Script();

  for (let i = 0; i < size; i++) {
    const len = rand(0, 100);
    script.pushData(random.randomBytes(len));
  }

  if (redeem)
    script.pushData(redeem);

  return script.compile();
}

function randomOutputScript() {
  const size = rand(1, 10000);
  return Script.fromRaw(random.randomBytes(size));
}

function isPushOnly(script) {
  if (script.isPushOnly())
    return true;

  for (const op of script.code) {
    if (op.value === Script.opcodes.NOP)
      continue;

    if (op.value === Script.opcodes.NOP_1)
      continue;

    if (op.value > Script.opcodes.NOP_3)
      continue;

    return false;
  }

  return true;
}

function randomPubkey() {
  const len = rand(0, 2) === 0 ? 33 : 65;
  return Script.fromPubkey(random.randomBytes(len));
}

function randomPubkeyhash() {
  return Script.fromPubkeyhash(random.randomBytes(20));
}

function randomMultisig() {
  const n = rand(1, 16);
  const m = rand(1, n);
  const keys = [];

  for (let i = 0; i < n; i++) {
    const len = rand(0, 2) === 0 ? 33 : 65;
    keys.push(random.randomBytes(len));
  }

  return Script.fromMultisig(m, n, keys);
}

function randomScripthash() {
  return Script.fromScripthash(random.randomBytes(20));
}

function randomWitnessPubkeyhash() {
  return Script.fromProgram(0, random.randomBytes(20));
}

function randomWitnessScripthash() {
  return Script.fromProgram(0, random.randomBytes(32));
}

function randomProgram() {
  const version = rand(0, 16);
  const size = rand(2, 41);
  return Script.fromProgram(version, random.randomBytes(size));
}

function randomRedeem() {
  switch (rand(0, 5)) {
    case 0:
      return randomPubkey();
    case 1:
      return randomPubkeyhash();
    case 2:
      return randomMultisig();
    case 3:
      return randomWitnessPubkeyhash();
    case 4:
      return randomProgram();
  }
  throw new Error();
}

function randomScript() {
  switch (rand(0, 7)) {
    case 0:
      return randomPubkey();
    case 1:
      return randomPubkeyhash();
    case 2:
      return randomMultisig();
    case 3:
      return randomScripthash();
    case 4:
      return randomWitnessPubkeyhash();
    case 5:
      return randomWitnessScripthash();
    case 6:
      return randomProgram();
  }
  throw new Error();
}

function randomPubkeyContext() {
  return {
    input: randomInputScript(),
    witness: new Witness(),
    output: randomPubkey(),
    redeem: null
  };
}

function randomPubkeyhashContext() {
  return {
    input: randomInputScript(),
    witness: new Witness(),
    output: randomPubkeyhash(),
    redeem: null
  };
}

function randomScripthashContext() {
  const redeem = randomRedeem();
  return {
    input: randomInputScript(redeem.toRaw()),
    witness: new Witness(),
    output: Script.fromScripthash(redeem.hash160()),
    redeem: redeem
  };
}

function randomWitnessPubkeyhashContext() {
  return {
    input: new Script(),
    witness: randomWitness(),
    output: randomWitnessPubkeyhash(),
    redeem: null
  };
}

function randomWitnessScripthashContext() {
  const redeem = randomRedeem();
  return {
    input: new Script(),
    witness: randomWitness(redeem.toRaw()),
    output: Script.fromProgram(0, redeem.sha256()),
    redeem: redeem
  };
}

function randomWitnessNestedContext() {
  const redeem = randomRedeem();
  const program = Script.fromProgram(0, redeem.sha256());
  return {
    input: Script.fromItems([program.toRaw()]),
    witness: randomWitness(redeem.toRaw()),
    output: Script.fromScripthash(program.hash160()),
    redeem: redeem
  };
}

function randomContext() {
  switch (rand(0, 6)) {
    case 0:
      return randomPubkeyContext();
    case 1:
      return randomPubkeyhashContext();
    case 2:
      return randomScripthashContext();
    case 3:
      return randomWitnessPubkeyhashContext();
    case 4:
      return randomWitnessScripthashContext();
    case 5:
      return randomWitnessNestedContext();
  }
  throw new Error();
}

function fuzzSimple(flags) {
  let tx = randomTX();
  let total = -1;

  for (;;) {
    if (++total % 1000 === 0)
      console.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    const stack = new Stack();
    const input = randomInputScript();

    try {
      input.execute(stack, flags, tx, 0, 0, 0);
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    const output = randomOutputScript();

    try {
      output.execute(stack, flags, tx, 0, 0, 0);
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    if (stack.length === 0)
      continue;

    if (!stack.getBool(-1))
      continue;

    if (isPushOnly(output))
      continue;

    console.log('Produced valid scripts:');

    console.log('Input:');
    console.log(input);

    console.log('Output:');
    console.log(output);

    console.log('Stack:');
    console.log(stack);

    break;
  }
}

function fuzzVerify(flags) {
  let tx = randomTX();
  let total = -1;

  for (;;) {
    if (++total % 1000 === 0)
      console.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    const input = randomInputScript();
    const witness = randomWitness();
    const output = randomOutputScript();

    tx.inputs[0].script = input;
    tx.inputs[0].witness = witness;

    tx.refresh();

    try {
      Script.verify(
        input,
        witness,
        output,
        tx,
        0,
        0,
        flags
      );
    } catch (e) {
      if (e.type === 'ScriptError') {
        assertConsensus(tx, output, flags, e.code);
        continue;
      }
      throw e;
    }

    assertConsensus(tx, output, flags, 'OK');

    if (isPushOnly(output))
      continue;

    console.log('Produced valid scripts:');

    console.log('Input:');
    console.log(input);

    console.log('Witness:');
    console.log(witness);

    console.log('Output:');
    console.log(output);

    break;
  }
}

function fuzzLess(flags) {
  let tx = randomTX();
  let total = -1;

  for (;;) {
    if (++total % 1000 === 0)
      console.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    const ctx = randomContext();
    const input = tx.inputs[0];

    input.script = ctx.input;
    input.witness = ctx.witness;

    tx.refresh();

    try {
      Script.verify(
        ctx.input,
        ctx.witness,
        ctx.output,
        tx,
        0,
        0,
        flags
      );
    } catch (e) {
      if (e.type === 'ScriptError') {
        assertConsensus(tx, ctx.output, flags, e.code);
        continue;
      }
      throw e;
    }

    assertConsensus(tx, ctx.output, flags, 'OK');

    console.log('Produced valid scripts:');

    console.log('Input:');
    console.log(ctx.input);

    console.log('Witness:');
    console.log(ctx.witness);

    console.log('Output:');
    console.log(ctx.output);

    if (ctx.redeem) {
      console.log('Redeem:');
      console.log(ctx.redeem);
    }

    break;
  }
}

function main() {
  const flags = process.argv.indexOf('--standard') !== -1
    ? STANDARD
    : MANDATORY;

  switch (process.argv[2]) {
    case 'simple':
      fuzzSimple(flags);
      break;
    case 'verify':
      fuzzVerify(flags);
      break;
    case 'less':
      fuzzLess(flags);
      break;
    default:
      console.log('Please select a mode:');
      console.log('simple, verify, less');
      console.log('Optional `--standard` flag.');
      break;
  }
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
}

randomKey;
randomSignature;

main();
