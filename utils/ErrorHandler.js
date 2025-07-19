const AppError = require("../utils/AppError");

const errorHandler = (req, res, next) => {
  res.status(404).json({
    status: "fail",
    message: `Can't find ${req.originalUrl} on this server!`,
  });
};

const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = `${err.statusCode}`.startsWith("4") ? "fail" : "error";

  if (err.name === "ValidationError") {
    err = new AppError("Invalid input data.", 400);
  }

  if (err.name === "JsonWebTokenError") {
    err = new AppError("Invalid token, please log in again!", 401);
  }

  if (err.name === "TokenExpiredError") {
    err = new AppError("Token expired, please log in again!", 401);
  }

  if (err.code === 11000) {
    err = new AppError(`Duplicate ${Object.keys(err.keyValue)} Entered`, 400);
  }

  if (process.env.NODE_ENV === "development") {
    console.error("💥 ERROR: ", err);
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      stack: err.stack,
      err: err,
    });
  } else {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.isOperational ? err.message : "Something went very wrong!",
    });
  }
};

module.exports = {
  errorHandler,
  globalErrorHandler,
};