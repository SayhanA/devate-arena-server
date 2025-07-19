const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
      select: false,
    },
    name: {
      type: String,
      required: true,
    },
    lastLogin: {
      type: Date,
      default: Date.now,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    profilePicture: {
      type: String,
      default:
        'https://t3.ftcdn.net/jpg/02/99/04/20/360_F_299042079_vGBD7wIlSeNl7vOevWHiL93G4koMM967.jpg',
    },
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordExpiredAt: {
      type: Date,
      select: false,
    },
    verificationToken: {
      type: String,
      select: false,
    },
    verificationTokenExpiredAt: {
      type: Date,
      select: false,
    },
    refreshToken: {
      type: String,
      default: null,
      select: false,
    },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    return next();
  } catch (error) {
    return next(error);
  }
});

userSchema.pre('save', async function (next) {
  if (!this.isVerified && !this.verificationToken) {
    this.verificationToken = Math.floor(10000 + Math.random() * 90000).toString();
    this.verificationTokenExpiredAt = Date.now() + 15 * 60 * 1000;
  }
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    if (!this.password) {
      const userWithPassword = await this.model('User').findById(this._id).select('+password');

      if (!userWithPassword) {
        throw new Error('User not found');
      }

      return await bcrypt.compare(candidatePassword, userWithPassword.password);
    }

    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    console.error('Password comparison error:', error);
    throw new Error('Password comparison failed');
  }
};

userSchema.methods.generateAccessToken = function () {
  const payload = {
    id: this._id,
    email: this.email,
    role: this.role,
  };

  const options = {
    expiresIn: '5m',
  };

  return jwt.sign(payload, process.env.JWT_ACCESSTOKEN_SECRET, options);
};

userSchema.methods.generateRefreshToken = async function () {
  const payload = {
    id: this._id,
    email: this.email,
    role: this.role,
  };

  const options = {
    expiresIn: '30d',
  };

  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESHTOKEN_SECRET, options);
  this.refreshToken = refreshToken;
  await this.save();
  return refreshToken;
};

module.exports = mongoose.model('User', userSchema);
