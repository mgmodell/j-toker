const HtmlWebPackPlugin = require('html-webpack-plugin');

const demoHtml = new HtmlWebPackPlugin({
  chunks: ['demo'],
  filename: './demo/index.html',
  minify: true,
  template: './demo/index.html',
});

module.exports = {
  entry: {
    index: './src/index.js',
    'demo/index': './demo/src/index.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
        },
      },
    ],
  },
  plugins: [demoHtml],
};
