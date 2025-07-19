const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth.js');
const { errorHandler, globalErrorHandler } = require('./utils/ErrorHandler.js');

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('API is running...');
});

app.use('/api/v1/en/auth', authRoutes);

app.use(errorHandler);
app.use(globalErrorHandler);

module.exports = app;
