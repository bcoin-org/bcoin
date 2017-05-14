const webpack = require('webpack')

module.exports = {
  entry: {
    'bcoin.min': './lib/bcoin',
    'bcoin-master.min': './lib/workers/master'
  },
  output: {
    path: './browser',
    filename: '[name].js'
  },
  resolve: {
    extensions: ['', '.js', '.json'],
    packageAlias: 'browser'
  },
  module: {
    loaders: [
      { test: /\.js$/, loader: 'babel', exclude: /node_modules/ },
      { test: /\.json$/, loader: 'json' }
    ]
  },
  node: {
    fs: 'empty'
  },
  plugins: [
    new webpack.optimize.UglifyJsPlugin({
      compress: {
        warnings: false
      }
    })
  ]
}
