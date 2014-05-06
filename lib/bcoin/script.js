var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var script = exports;

script.decode = function decode(s) {
  if (!s)
    return [];
  var opcodes = [];
  for (var i = 0; i < s.length;) {
    var b = s[i++];

    // Next `b` bytes should be pushed to stack
    if (b >= 0x01 && b <= 0x4b) {
      opcodes.push(s.slice(i, i + b));
      i += b;
      continue;
    }

    // Zero
    if (b === 0) {
      opcodes.push([]);
      continue;
    }

    // Raw number
    if (b >= 0x51 && b <= 0x60) {
      opcodes.push([ b - 0x50 ]);
      continue;
    }

    var opcode = constants.opcodesByVal[b];
    if (opcode === 'pushdata1') {
      var len = s[i++];
      opcodes.push(s.slice(i, i + len));
      i += 2 + len;
    } else if (opcode === 'pushdata2') {
      var len = readU16(s, i);
      i += 2;
      opcodes.push(s.slice(i, i + len));
      i += len;
    } else if (opcode === 'pushdata4') {
      var len = readU32(s, i);
      i += 4;
      opcodes.push(s.slice(i, i + len));
      i += len;
    } else {
      opcodes.push(opcode || b);
    }
  }
  return opcodes;
};

script.encode = function encode(s) {
  if (!s)
    return [];
  var opcodes = constants.opcodes;
  var res = [];
  for (var i = 0; i < s.length; i++) {
    var instr = s[i];

    // Push value to stack
    if (Array.isArray(instr)) {
      if (instr.length === 0) {
        res.push(0);
      } else if (instr.length === 1 && 0 < instr[0] && instr[0] <= 16) {
        res.push(0x50 + instr[0]);
      } else if (1 <= instr.length && instr.length <= 0x4b) {
        res = res.concat(instr.length, instr);
      } else if (instr.length <= 0xff) {
        res = res.concat(opcodes['pushdata1'], instr.length, instr);
      } else if (instr.length <= 0xffff) {
        res.push(opcodes['pushdata2']);
        utils.writeU16(res, instr.length, res.length);
        res = res.concat(instr);
      } else {
        res.push(opcodes['pushdata4']);
        utils.writeU32(res, instr.length, res.length);
        res = res.concat(instr);
      }
      continue;
    }

    res.push(opcodes[instr] || instr);
  }

  return res;
};

script.subscript = function subscript(s) {
  if (!s)
    return [];

  var lastSep = -1;
  for (var i = 0; i < s.length; i++) {
    if (s[i] === 'codesep')
      lastSep = i;
    else if (s[i] === 'checksig' ||
             s[i] === 'checksigverify' ||
             s[i] === 'checkmultisig' ||
             s[i] === 'checkmultisigverify') {
      break;
    }
  }

  var res = [];
  for (var i = lastSep + 1; i < s.length; i++)
    if (s[i] !== 'codesep')
      res.push(s[i]);

  return res;
};

script.execute = function execute(s, stack, tx) {
  for (var i = 0; i < s.length; i++) {
    var o = s[i];
    if (Array.isArray(o)) {
      stack.push(o);
    } else if (o === 'dup') {
      if (stack.length === 0)
        return false;

      stack.push(stack[stack.length - 1]);
    } else if (o === 'hash160') {
      if (stack.length === 0)
        return false;

      stack.push(utils.ripesha(stack.pop()));
    } else if (o === 'eqverify' || o === 'eq') {
      if (stack.length < 2)
        return false;

      var res = utils.isEqual(stack.pop(), stack.pop());
      if (o === 'eqverify') {
        if (!res)
          return false;
      } else {
        stack.push(res ? [ 1 ] : []);
      }

    } else if (o === 'checksigverify' || o === 'checksig') {
      if (!tx || stack.length < 2)
        return false;

      var pub = stack.pop();
      var sig = stack.pop();
      var type = sig[sig.length - 1];
      if (type !== 1)
        return false;

      var res = bcoin.ecdsa.verify(tx, sig, pub);
      if (o === 'checksigverify') {
        if (!res)
          return false;
      } else {
        stack.push(res ? [ 1 ] : []);
      }
    } else {
      // Unknown operation
      return false;
    }
  }

  return true;
};

script.isPubkeyhash = function isPubkeyhash(s, hash) {
  if (s.length !== 5)
    return false;

  var match = s[0] === 'dup' &&
              s[1] === 'hash160' &&
              Array.isArray(s[2]) &&
              s[3] === 'eqverify' &&
              s[4] === 'checksig';
  if (!match)
    return false;

  if (hash)
    return utils.isEqual(s[2], hash);
  else
    return s[2];
}

script.isMultisig = function isMultisig(s, key) {
  if (s.length < 4)
    return false;

  var m = s[0];
  if (!Array.isArray(m) || m.length !== 1)
    return false;
  m = m[0];

  if (m + 3 !== s.length || s[s.length - 1] !== 'checkmultisig')
    return false;

  var n = s[s.length - 2];
  if (!Array.isArray(n) || n.length !== 1)
    return false;

  var keys = s.slice(1, m);
  var isArray = keys.every(function(k) {
    return Array.isArray(k);
  });
  if (!isArray)
    return false;

  if (!key)
    return keys;

  return m === keys.filter(function(k) {
    return utils.isEqual(k, key);
  }).length;
}
