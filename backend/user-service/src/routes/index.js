// const adminRoute = require("./adminRoute");
const userRoute = require("./userRoute");

const mountRoutes = (app) => {
  // app.use("/admin", adminRoute);
  app.use("/api/v1", userRoute);
};

module.exports = mountRoutes;
