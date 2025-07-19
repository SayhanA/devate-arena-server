const { validationResult } = require('express-validator');
const AppError = require('../utils/AppError');
const User = require('../models/user');

function expressErrorHandler(req) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new AppError(
        errors
          .array()
          .map((e) => `${e.param}: ${e.msg}`)
          .join(' | '),
        400
      )
    );
  }
}

exports.register = async (req, res, next) => {
  expressErrorHandler(req);

  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new AppError('Email already in use', 400));
    }

    const newUser = await User.create({
      name,
      email,
      password,
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: newUser,
    });
  } catch (error) {
    console.log({ error });
    return next(new AppError('SomeThing went wrong in Registration', 500));
  }
};

exports.verify = async (req, res, next) => {
  expressErrorHandler(req);

  try {
    const { token, email } = req.body;
    console.log({ token, email });

    const user = await User.findOne({
      email,
      verificationToken: token,
      verificationTokenExpiredAt: { $gt: Date.now() },
    }).select('+verificationToken +verificationTokenExpiredAt');

    if (!user) {
      return next(new AppError('Invalid or expired verification token', 400));
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiredAt = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Account verified successfully',
    });
  } catch (error) {
    console.error(error);
    return next(new AppError('Something went wrong in Verification', 500));
  }
};

exports.login = async (req, res, next) => {
  expressErrorHandler(req);

  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return next(new AppError('Invalid email or password', 401));
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return next(new AppError('Invalid email or password', 401));
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      accessToken,
      user,
    });
  } catch (error) {
    console.error(error);
    return next(new AppError('Something went wrong in login', 500));
  }
};
