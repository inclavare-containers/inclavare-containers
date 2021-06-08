const path = require("path");

const join = (...paths) => path.join(__dirname, ...paths);

module.exports = {
  entry: {
    app: "./assets/js/app.js",
    main: "./assets/sass/main.scss",
  },
  output: {
    filename: "[name].js",
    path: join("static/js"),
  },
  performance: {
    hints: false,
  },
  module: {
    rules: [{
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
          options: {
            presets: ["@babel/preset-env"],
          },
        },
      },
      {
        test: /\.svg$/,
        use: {
          loader: 'raw-loader',
        },
      },
      {
        test: /\.css$/,
        use: {
          loader: 'file-loader',
          options: {
            name: '[name].css',
            outputPath: '../css/'
          }
        },
      },
      {
        test: /\.scss$/,
        use: [{
            loader: 'file-loader',
            options: {
              name: '[name].css',
              outputPath: '../css/'
            }
          },
          {
            loader: "sass-loader",
            options: {
              outputStyle: 'compressed',
            },
          },
        ]
      },
    ],
  },
};