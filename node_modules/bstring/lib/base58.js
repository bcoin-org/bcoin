'use strict';

try {
  module.exports = require('./binding').base58;
} catch (e) {
  module.exports = require('./base58-browser');
}
