'use strict';

try {
  module.exports = require('./binding').bech32;
} catch (e) {
  module.exports = require('./bech32-browser');
}
