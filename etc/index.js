module.exports = [
  'var fs = require(\'fs\');',
  'var util = require(\'util\');',
  '',
  'fs.readdirSync(\'./\').forEach(function(file) {',
  'if (file === \'lists\')',
  'return;',
  'var data = fs.readFileSync(file, \'utf8\');',
  'data = data.trim().split(/\\n/).map(function(data) {',
  'return data.trim();',
  '});',
  '//data = JSON.stringify(data, null, 2);',
  '//file = file.split(\'.\')[0
]; + \'.json\';',
  'data = util.inspect(data).replace(\'[\', \'module.exports = [\\n \').replace(\']\', \'\\n];\');',
  'file = file.split(\'.\')[0] + \'.js\';',
  'fs.writeFileSync(\'./lists/\' + file, data);',
  '});' ]