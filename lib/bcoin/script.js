var bcoin = require('../bcoin');
var constants = bcoin.protocol.constants;
var utils = bcoin.protocol.utils;
var script = exports;

script.decode = function decode(s) {
  if (!s)
    return [];
  var opcodes = [];
  for (var i = 0; i < s.length;) {
    var b = s[i++];

    // Next `b` bytes should be pushed to stack
    if (b >= 0x01 && b <= 0x75) {
      opcodes.push(s.slice(i, i + b));
      i += b;
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
      if (1 <= instr.length && instr.length <= 0x75) {
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
