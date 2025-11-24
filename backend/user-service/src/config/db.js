const mongoose = require('mongoose');

const dbConnection = () => {
  mongoose
    .connect(process.env.MONGODB_URI)
    .then((connect) => {
      console.log(`Database connected: ${connect.connection.host}:${connect.connection.port}/${connect.connection.name}`);
    })
};

module.exports = dbConnection;