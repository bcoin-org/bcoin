'use strict';

try {
  module.exports = require('./binding').cashaddr;
} catch (e) {
  module.exports = require('./cashaddr-browser');
}
