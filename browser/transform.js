var assert = require('assert');
var Transform = require('stream').Transform;
var path = require('path');
var StringDecoder = require('string_decoder').StringDecoder;

function nil() {
  var stream = new Transform();

  stream._transform = function(chunk, encoding, callback) {
    callback(null, chunk);
  };

  stream._flush = function(callback) {
    callback();
  };

  return stream;
}

function processEnv(str) {
  return str.replace(
    /^( *)this\.require\('(\w+)', '([^']+)'\)/gm,
    '$1this.$2 = require(\'$3\')');
}

function transformer(file, process) {
  var stream = new Transform();
  var decoder = new StringDecoder('utf8');
  var str = '';

  stream._transform = function(chunk, encoding, callback) {
    assert(Buffer.isBuffer(chunk));
    str += decoder.write(chunk);
    callback(null, new Buffer(0));
  };

  stream._flush = function(callback) {
    str = process(str);

    stream.push(new Buffer(str, 'utf8'));

    callback();
  };

  return stream;
}

function end(file, offset) {
  return path.normalize(file).split(path.sep).slice(-offset).join('/');
}

module.exports = function(file) {
  if (end(file, 2) === 'lib/env.js')
    return transformer(file, processEnv);

  return nil();
};
