const { validationResult } = require('express-validator');
const AppError = require('../utils/AppError');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
require('dotenv').config();

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

    const user = await User.findOne({ email, isVerified: true });
    if (!user) {
      return next(new AppError('Invalid email or password', 401));
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return next(new AppError('Invalid email or password', 401));
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken();

    user.lastLogin = Date.now();
    await user.save();

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

exports.getUser = async (req, res, next) => {
  expressErrorHandler(req);

  try {
    if (!req.user) {
      return next(new AppError('Please login first', 401));
    }

    const user = await User.findById(req.user._id);

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    res.status(200).json({
      success: true,
      message: 'User successfully fetched',
      user,
    });
  } catch (error) {
    console.error('Get user error:', error);
    return next(new AppError('Failed to fetch user', 500));
  }
};

exports.refreshToken = async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return res.status(401).json({ message: 'No refresh token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_REFRESHTOKEN_SECRET);

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newAccessToken = user.generateAccessToken();
    const newRefreshToken = await user.generateRefreshToken();

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
};

exports.logout = async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return res.status(400).json({ message: 'No refresh token found in cookies' });
    }

    const user = await User.findOne({ refreshToken: token }).select('+refreshToken');

    if (user) {
      user.refreshToken = null;
      await user.save();
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    next(error);
  }
};
