const express = require("express");
const dotenv = require("dotenv");
dotenv.config({ path: "../../.env" });
const morgan = require("morgan");
const cors = require("cors");
const compression = require("compression");
const mongoSanitize = require("express-mongo-sanitize");
const { xss } = require("express-xss-sanitizer");
const ApiError = require("./utils/apiError");
const globalError = require("./middleware/errorMiddleware");
const dbConnection = require("./config/db");

// Routes
const mountRoutes = require("./routes");

// Connect with db
dbConnection();

// express app
const app = express();

// Enable other domains to access your application
app.use(cors());
app.options("*", cors());

// compress all responses
app.use(compression());

// Middlewares
app.use(express.json({ limit: "20kb" }));

if (process.env.USER_BACKEND_ENV === "development") {
  app.use(morgan("dev"));
  console.log(`mode: ${process.env.USER_BACKEND_ENV}`);
}

// Data Sanitization :
// By default, $ and . characters are removed completely from user-supplied input in the following places:
app.use(mongoSanitize());
app.use(xss());

// Mount Routes
mountRoutes(app);

app.all("*", (req, res, next) => {
  next(new ApiError(`Cannot find this route: ${req.originalUrl}`, 400));
});

// Global error handling middleware for express
app.use(globalError);

const PORT = process.env.USER_BACKEND_PORT || 8002;
const server = app.listen(PORT, () => {
  console.log(`Application running on port ${PORT}`);
});

// Handle rejection outside express
process.on("unhandledRejection", (err) => {
  console.error(`UnhandledRejection Errors: ${err.name} | ${err.message}`);
  server.close(() => {
    console.error(`Shutting down....`);
    process.exit(1);
  });
});