/*!
 * parser.js - packet parser
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const Frame = require('./frame');

const MAX_MESSAGE = 100000000;

class Parser extends EventEmitter {
  constructor() {
    super();
  }

  error(msg) {
    this.emit('error', new Error(msg));
  }

  feedBinary(data) {
    assert(Buffer.isBuffer(data));

    if (data.length > MAX_MESSAGE) {
      this.error('Frame too large.');
      return;
    }

    let frame;
    try {
      frame = Frame.fromRaw(data);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('frame', frame);
  }

  feedString(data) {
    assert(typeof data === 'string');

    if (Buffer.byteLength(data, 'utf8') > MAX_MESSAGE) {
      this.error('Frame too large.');
      return;
    }

    let frame;
    try {
      frame = Frame.fromString(data);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.emit('frame', frame);
  }
}

/*
 * Expose
 */

module.exports = Parser;
