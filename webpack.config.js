const webpack = require('webpack')
const PATHS = {
  bcoin: './lib/bcoin',
  master: './lib/workers/master'
}
module.exports = {
  entry: {
    'bcoin': PATHS.bcoin,
    'bcoin.min': PATHS.bcoin,
    'bcoin-master': PATHS.master,
    'bcoin-master.min': PATHS.master
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
        },
        include: /\.min\.js$/,
        minimize: true
    })
  ]
}
