import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import catchAsync from '../utils/catchAsync.js';
import appError from '../utils/appError.js';

/**
 * Authentication middleware to verify JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object  
 * @param {Function} next - Express next function
 */
const authMiddleware = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new appError('You are not logged in! Please log in to get access.', 401));
  }

  // 2) Verification of token
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new appError('Invalid token. Please log in again!', 401));
    } else if (error.name === 'TokenExpiredError') {
      return next(new appError('Your token has expired! Please log in again.', 401));
    }
    return next(new appError('Token verification failed!', 401));
  }

  // 3) Check if user still exists (optional - requires User model)
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new appError('The user belonging to this token does no longer exist.', 401));
  }
  

  // 4) Check if user changed password after the token was issued (optional)
  /*
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new appError('User recently changed password! Please log in again.', 401));
  }
  */

  // Grant access to protected route
  req.user = decoded; // or req.user = currentUser if using database check
  next();
});

/**
 * Middleware to restrict access to specific roles
 * @param {...string} roles - Allowed roles
 * @returns {Function} Express middleware function
 */

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new appError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

/**
 * Optional middleware for routes that may or may not require authentication
 * Sets req.user if valid token is provided, but doesn't block access if not
 */
const optionalAuth = catchAsync(async (req, res, next) => {
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
    } catch (error) {
      // Token is invalid but we don't throw error for optional auth
      req.user = null;
    }
  }

  next();
});

export { authMiddleware, restrictTo, optionalAuth };