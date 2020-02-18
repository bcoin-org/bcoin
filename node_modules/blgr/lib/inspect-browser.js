'use strict';

module.exports = function inspect(obj) {
  if (obj === undefined)
    return 'undefined';

  if (obj !== obj)
    return 'NaN';

  try {
    return JSON.stringify(obj, null, 2);
  } catch (e) {
    return '{}';
  }
};
