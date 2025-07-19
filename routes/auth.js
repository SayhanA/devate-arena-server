const express = require('express');
const { register, login, verify } = require('../controllers/auth');
const { body } = require('express-validator');
const router = express.Router();

router.post(
  '/register',
  body('name', 'Name is required!').trim(),
  body('email', 'Email is required!').isEmail().trim(),
  body('password', 'Password is required!').trim(),
  register
);

router.post(
  '/verify',
  body('token', 'Token is required!').trim(),
  body('email', 'Email is required!').isEmail().trim(),
  verify
);

router.post(
  '/login',
  body('email', 'Email is required!').isEmail().trim(),
  body('password', 'Password is required!').trim(),
  login
);

module.exports = router;
