import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import AppError from '../utils/appError.js';
import catchAsync from '../utils/catchAsync.js'; 
import emailService from '../utils/emailService.js'; 

// Generate JWT token
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

// Create and send token response
const createSendToken = (user, statusCode, res, message = 'Success') => {
  const token = signToken(user._id);
  
  const cookieOptions = {
    expires: new Date(
      Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 7) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    message,
    token,
    data: {
      user
    }
  });
};

// Admin registration (restricted)
export const registerAdmin = catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, password, adminSecret } = req.body;

  // Check admin secret key
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET_KEY) {
    return next(new AppError('Invalid admin secret key', 403));
  }

  // Check if admin already exists
  const existingAdmin = await User.findOne({ role: 'admin' });
  if (existingAdmin) {
    return next(new AppError('Admin already exists. Only one admin is allowed.', 400));
  }

  // Check if user with email already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }

  // Create admin user
  const newAdmin = await User.create({
    firstName,
    lastName,
    email,
    password,
    role: 'admin',
    isVerified: true // Admin is auto-verified
  });

  createSendToken(newAdmin, 201, res, 'Admin registered successfully');
});

// Regular user registration
export const register = catchAsync(async (req, res, next) => {
  const {
    firstName,
    lastName,
    email,
    password,
    role,
    phone,
    address,
    organization
  } = req.body;

  // Prevent admin registration through regular endpoint
  if (role === 'admin') {
    return next(new AppError('Admin registration not allowed through this endpoint', 400));
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }

  // Validate role-specific requirements
  if ((role === 'restaurant_owner' || role === 'food_bank') && !organization?.name) {
    return next(new AppError('Organization name is required for this role', 400));
  }

  // Create user data object
  const userData = {
    firstName,
    lastName,
    email,
    password,
    role: role || 'donor'
  };

  // Add optional fields if provided
  if (phone) userData.phone = phone;
  if (address) userData.address = address;
  if (organization) userData.organization = organization;

  // Create new user
  const newUser = await User.create(userData);

  // Generate email verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  newUser.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  newUser.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  await newUser.save({ validateBeforeSave: false });

  // Send welcome and verification email
  try {
    await emailService.sendWelcomeEmail(newUser, verificationToken);
  } catch (err) {
    console.error('Email sending failed:', err);
    // Don't fail registration if email fails
  }

  createSendToken(newUser, 201, res, 'User registered successfully. Please check your email to verify your account.');
});

// User login
export const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  // Check if user exists and password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.comparePassword(password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // Check if user account is active
  if (!user.isActive) {
    return next(new AppError('Your account has been deactivated. Please contact support.', 401));
  }

  // Update last login
  user.lastLogin = new Date();
  await user.save({ validateBeforeSave: false });

  createSendToken(user, 200, res, 'Login successful');
});

// Logout
export const logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({ 
    status: 'success',
    message: 'Logged out successfully'
  });
};

// Protect middleware - check if user is authenticated
export const protect = catchAsync(async (req, res, next) => {
  // Get token and check if it exists
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new AppError('You are not logged in! Please log in to get access.', 401));
  }

  // Verify token
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  // Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  // Check if user is active
  if (!currentUser.isActive) {
    return next(new AppError('Your account has been deactivated. Please contact support.', 401));
  }

  // Grant access to protected route
  req.user = currentUser;
  next();
});

// Restrict access to specific roles
export const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

// Admin only middleware
export const adminOnly = restrictTo('admin');

// Email verification
export const verifyEmail = catchAsync(async (req, res, next) => {
  // Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() }
  });

  // If token has not expired, and there is user, verify email
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  user.isVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'Email verified successfully'
  });
});

// Resend verification email
export const resendVerificationEmail = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new AppError('Please provide your email address', 400));
  }

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError('No user found with that email address', 404));
  }

  if (user.isVerified) {
    return next(new AppError('Email is already verified', 400));
  }

  // Generate new verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  user.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  await user.save({ validateBeforeSave: false });

  // Send verification email
  try {
    await emailService.sendWelcomeEmail(user, verificationToken);
    
    res.status(200).json({
      status: 'success',
      message: 'Verification email sent successfully'
    });
  } catch (err) {
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later.', 500));
  }
});

// Forgot password
export const forgotPassword = catchAsync(async (req, res, next) => {
  // Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with that email address.', 404));
  }

  // Generate the random reset token
  const resetToken = crypto.randomBytes(32).toString('hex');

  user.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  await user.save({ validateBeforeSave: false });

  // Send it to user's email
  try {
    await emailService.sendPasswordResetEmail(user, resetToken);

    res.status(200).json({
      status: 'success',
      message: 'Password reset link sent to your email'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later.', 500));
  }
});

// Reset password
export const resetPassword = catchAsync(async (req, res, next) => {
  // Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  // If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // Send password change confirmation email
  try {
    await emailService.sendPasswordChangeConfirmation(user);
  } catch (err) {
    console.error('Password change confirmation email failed:', err);
  }

  // Log user in, send JWT
  createSendToken(user, 200, res, 'Password reset successful');
});

// Get current user
export const getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  
  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

// Update current user data (not password)
export const updateMe = catchAsync(async (req, res, next) => {
  // Create error if user POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
  }

  // Filter out unwanted fields that are not allowed to be updated
  const allowedFields = ['firstName', 'lastName', 'phone', 'address', 'organization', 'preferences'];
  const filteredBody = {};
  
  Object.keys(req.body).forEach(el => {
    if (allowedFields.includes(el)) {
      filteredBody[el] = req.body[el];
    }
  });

  // Update user document
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    status: 'success',
    message: 'User updated successfully',
    data: {
      user: updatedUser
    }
  });
});

// Change password
export const updatePassword = catchAsync(async (req, res, next) => {
  // Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  // Check if current password is correct
  if (!(await user.comparePassword(req.body.passwordCurrent))) {
    return next(new AppError('Your current password is incorrect.', 401));
  }

  // Update password
  user.password = req.body.password;
  await user.save();

  // Send password change confirmation email
  try {
    await emailService.sendPasswordChangeConfirmation(user);
  } catch (err) {
    console.error('Password change confirmation email failed:', err);
  }

  // Log user in, send JWT
  createSendToken(user, 200, res, 'Password updated successfully');
});

// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import User from '../models/User.js';
// import AppError from '../utils/appError.js';
// import catchAsync from '../utils/catchAsync.js'; 
// import emailService from '../utils/emailService.js'; 

// // Generate JWT token
// const signToken = (id) => {
//   return jwt.sign({ id }, process.env.JWT_SECRET, {
//     expiresIn: process.env.JWT_EXPIRES_IN || '7d'
//   });
// };

// // Create and send token response
// const createSendToken = (user, statusCode, res, message = 'Success') => {
//   const token = signToken(user._id);
  
//   const cookieOptions = {
//     expires: new Date(
//       Date.now() + (process.env.JWT_COOKIE_EXPIRES_IN || 7) * 24 * 60 * 60 * 1000
//     ),
//     httpOnly: true,
//     secure: process.env.NODE_ENV === 'production',
//     sameSite: 'strict'
//   };

//   res.cookie('jwt', token, cookieOptions);

//   // Remove password from output
//   user.password = undefined;

//   res.status(statusCode).json({
//     status: 'success',
//     message,
//     token,
//     data: {
//       user
//     }
//   });
// };

// // Admin registration (restricted)
// export const registerAdmin = catchAsync(async (req, res, next) => {
//   const { firstName, lastName, email, password, adminSecret } = req.body;

//   // Check admin secret key
//   if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET_KEY) {
//     return next(new AppError('Invalid admin secret key', 403));
//   }

//   // Check if admin already exists
//   const existingAdmin = await User.findOne({ role: 'admin' });
//   if (existingAdmin) {
//     return next(new AppError('Admin already exists. Only one admin is allowed.', 400));
//   }

//   // Check if user with email already exists
//   const existingUser = await User.findOne({ email });
//   if (existingUser) {
//     return next(new AppError('User with this email already exists', 400));
//   }

//   // Create admin user
//   const newAdmin = await User.create({
//     firstName,
//     lastName,
//     email,
//     password,
//     role: 'admin',
//     isVerified: true // Admin is auto-verified
//   });

//   // Send welcome email to admin
//   try {
//     await emailService.sendWelcomeEmail(
//       newAdmin.email,
//       `${newAdmin.firstName} ${newAdmin.lastName}`
//     );
//   } catch (error) {
//     console.error('Failed to send admin welcome email:', error);
//     // Don't fail registration if email fails
//   }

//   createSendToken(newAdmin, 201, res, 'Admin registered successfully');
// });

// // Regular user registration
// export const register = catchAsync(async (req, res, next) => {
//   const {
//     firstName,
//     lastName,
//     email,
//     password,
//     role,
//     phone,
//     address,
//     organization
//   } = req.body;

//   // Prevent admin registration through regular endpoint
//   if (role === 'admin') {
//     return next(new AppError('Admin registration not allowed through this endpoint', 400));
//   }

//   // Check if user already exists
//   const existingUser = await User.findOne({ email });
//   if (existingUser) {
//     return next(new AppError('User with this email already exists', 400));
//   }

//   // Validate role-specific requirements
//   if ((role === 'restaurant_owner' || role === 'food_bank') && !organization?.name) {
//     return next(new AppError('Organization name is required for this role', 400));
//   }

//   // Create user data object
//   const userData = {
//     firstName,
//     lastName,
//     email,
//     password,
//     role: role || 'donor'
//   };

//   // Add optional fields if provided
//   if (phone) userData.phone = phone;
//   if (address) userData.address = address;
//   if (organization) userData.organization = organization;

//   // Create new user
//   const newUser = await User.create(userData);

//   // Generate email verification token
//   const verificationToken = crypto.randomBytes(32).toString('hex');
//   newUser.emailVerificationToken = crypto
//     .createHash('sha256')
//     .update(verificationToken)
//     .digest('hex');
//   newUser.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

//   await newUser.save({ validateBeforeSave: false });

//   // Send verification email
//   try {
//     const baseUrl = `${req.protocol}://${req.get('host')}`;
    
//     await emailService.sendVerificationEmail(
//       newUser.email,
//       newUser.firstName,
//       verificationToken,
//       baseUrl
//     );
//   } catch (error) {
//     console.error('Failed to send verification email:', error);
//     // Reset verification token fields if email fails
//     newUser.emailVerificationToken = undefined;
//     newUser.emailVerificationExpires = undefined;
//     await newUser.save({ validateBeforeSave: false });
    
//     return next(new AppError('There was an error sending the verification email. Please try again.', 500));
//   }

//   createSendToken(newUser, 201, res, 'User registered successfully. Please check your email for verification instructions.');
// });

// // User login
// export const login = catchAsync(async (req, res, next) => {
//   const { email, password } = req.body;

//   // Check if email and password exist
//   if (!email || !password) {
//     return next(new AppError('Please provide email and password', 400));
//   }

//   // Check if user exists and password is correct
//   const user = await User.findOne({ email }).select('+password');

//   if (!user || !(await user.comparePassword(password))) {
//     return next(new AppError('Incorrect email or password', 401));
//   }

//   // Check if user account is active
//   if (!user.isActive) {
//     return next(new AppError('Your account has been deactivated. Please contact support.', 401));
//   }

//   // Check if email is verified (except for admin)
//   if (!user.isVerified && user.role !== 'admin') {
//     return next(new AppError('Please verify your email address before logging in.', 401));
//   }

//   // Update last login
//   user.lastLogin = new Date();
//   await user.save({ validateBeforeSave: false });

//   createSendToken(user, 200, res, 'Login successful');
// });

// // Logout
// export const logout = (req, res) => {
//   res.cookie('jwt', 'loggedout', {
//     expires: new Date(Date.now() + 10 * 1000),
//     httpOnly: true
//   });
  
//   res.status(200).json({ 
//     status: 'success',
//     message: 'Logged out successfully'
//   });
// };

// // Protect middleware - check if user is authenticated
// export const protect = catchAsync(async (req, res, next) => {
//   // Get token and check if it exists
//   let token;
//   if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
//     token = req.headers.authorization.split(' ')[1];
//   } else if (req.cookies.jwt) {
//     token = req.cookies.jwt;
//   }

//   if (!token) {
//     return next(new AppError('You are not logged in! Please log in to get access.', 401));
//   }

//   // Verify token
//   const decoded = jwt.verify(token, process.env.JWT_SECRET);

//   // Check if user still exists
//   const currentUser = await User.findById(decoded.id);
//   if (!currentUser) {
//     return next(new AppError('The user belonging to this token does no longer exist.', 401));
//   }

//   // Check if user is active
//   if (!currentUser.isActive) {
//     return next(new AppError('Your account has been deactivated. Please contact support.', 401));
//   }

//   // Grant access to protected route
//   req.user = currentUser;
//   next();
// });

// // Restrict access to specific roles
// export const restrictTo = (...roles) => {
//   return (req, res, next) => {
//     if (!roles.includes(req.user.role)) {
//       return next(new AppError('You do not have permission to perform this action', 403));
//     }
//     next();
//   };
// };

// // Admin only middleware
// export const adminOnly = restrictTo('admin');

// // Email verification
// export const verifyEmail = catchAsync(async (req, res, next) => {
//   // Get user based on the token
//   const hashedToken = crypto
//     .createHash('sha256')
//     .update(req.params.token)
//     .digest('hex');

//   const user = await User.findOne({
//     emailVerificationToken: hashedToken,
//     emailVerificationExpires: { $gt: Date.now() }
//   });

//   // If token has not expired, and there is user, verify email
//   if (!user) {
//     return next(new AppError('Token is invalid or has expired', 400));
//   }

//   user.isVerified = true;
//   user.emailVerificationToken = undefined;
//   user.emailVerificationExpires = undefined;
//   await user.save({ validateBeforeSave: false });

//   // Send welcome email after successful verification
//   try {
//     await emailService.sendWelcomeEmail(
//       user.email,
//       `${user.firstName} ${user.lastName}`
//     );
//   } catch (error) {
//     console.error('Failed to send welcome email:', error);
//     // Don't fail verification if welcome email fails
//   }

//   res.status(200).json({
//     status: 'success',
//     message: 'Email verified successfully! Welcome to our platform.'
//   });
// });

// // Resend verification email
// export const resendVerificationEmail = catchAsync(async (req, res, next) => {
//   const { email } = req.body;

//   if (!email) {
//     return next(new AppError('Please provide email address', 400));
//   }

//   const user = await User.findOne({ email });

//   if (!user) {
//     return next(new AppError('No user found with that email address', 404));
//   }

//   if (user.isVerified) {
//     return next(new AppError('Email is already verified', 400));
//   }

//   // Generate new verification token
//   const verificationToken = crypto.randomBytes(32).toString('hex');
//   user.emailVerificationToken = crypto
//     .createHash('sha256')
//     .update(verificationToken)
//     .digest('hex');
//   user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

//   await user.save({ validateBeforeSave: false });

//   // Send verification email
//   try {
//     const baseUrl = `${req.protocol}://${req.get('host')}`;
    
//     await emailService.sendVerificationEmail(
//       user.email,
//       user.firstName,
//       verificationToken,
//       baseUrl
//     );

//     res.status(200).json({
//       status: 'success',
//       message: 'Verification email sent successfully'
//     });
//   } catch (error) {
//     console.error('Failed to send verification email:', error);
//     user.emailVerificationToken = undefined;
//     user.emailVerificationExpires = undefined;
//     await user.save({ validateBeforeSave: false });
    
//     return next(new AppError('There was an error sending the verification email. Please try again.', 500));
//   }
// });

// // Forgot password
// export const forgotPassword = catchAsync(async (req, res, next) => {
//   // Get user based on posted email
//   const user = await User.findOne({ email: req.body.email });
//   if (!user) {
//     return next(new AppError('There is no user with that email address', 404));
//   }

//   // Generate random reset token
//   const resetToken = crypto.randomBytes(32).toString('hex');
  
//   user.passwordResetToken = crypto
//     .createHash('sha256')
//     .update(resetToken)
//     .digest('hex');
//   user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

//   await user.save({ validateBeforeSave: false });

//   // Send password reset email
//   try {
//     const baseUrl = `${req.protocol}://${req.get('host')}`;
    
//     await emailService.sendPasswordResetEmail(
//       user.email,
//       `${user.firstName} ${user.lastName}`,
//       resetToken,
//       baseUrl
//     );

//     res.status(200).json({
//       status: 'success',
//       message: 'Password reset instructions sent to your email'
//     });
//   } catch (error) {
//     console.error('Failed to send password reset email:', error);
//     user.passwordResetToken = undefined;
//     user.passwordResetExpires = undefined;
//     await user.save({ validateBeforeSave: false });

//     return next(new AppError('There was an error sending the password reset email. Please try again.', 500));
//   }
// });

// // Reset password
// export const resetPassword = catchAsync(async (req, res, next) => {
//   // Get user based on the token
//   const hashedToken = crypto
//     .createHash('sha256')
//     .update(req.params.token)
//     .digest('hex');

//   const user = await User.findOne({
//     passwordResetToken: hashedToken,
//     passwordResetExpires: { $gt: Date.now() }
//   });

//   // If token has not expired, and there is user, set the new password
//   if (!user) {
//     return next(new AppError('Token is invalid or has expired', 400));
//   }

//   user.password = req.body.password;
//   user.passwordResetToken = undefined;
//   user.passwordResetExpires = undefined;
//   await user.save();

//   // Send password change confirmation email (optional - can be removed if not needed)
//   try {
//     // Since your emailService doesn't have a generic sendEmail method,
//     // we'll skip the password change notification for now
//     // You can add a sendNotificationEmail method to your emailService if needed
//     console.log('Password reset completed for user:', user.email);
//   } catch (error) {
//     console.error('Failed to send password change confirmation email:', error);
//     // Don't fail password reset if confirmation email fails
//   }

//   // Log user in, send JWT
//   createSendToken(user, 200, res, 'Password reset successful');
// });

// // Get current user
// export const getMe = catchAsync(async (req, res, next) => {
//   const user = await User.findById(req.user.id);
  
//   res.status(200).json({
//     status: 'success',
//     data: {
//       user
//     }
//   });
// });

// // Update current user data (not password)
// export const updateMe = catchAsync(async (req, res, next) => {
//   // Create error if user POSTs password data
//   if (req.body.password || req.body.passwordConfirm) {
//     return next(new AppError('This route is not for password updates. Please use /updateMyPassword.', 400));
//   }

//   // Filter out unwanted fields that are not allowed to be updated
//   const allowedFields = ['firstName', 'lastName', 'phone', 'address', 'organization', 'preferences'];
//   const filteredBody = {};
  
//   Object.keys(req.body).forEach(el => {
//     if (allowedFields.includes(el)) {
//       filteredBody[el] = req.body[el];
//     }
//   });

//   // Update user document
//   const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
//     new: true,
//     runValidators: true
//   });

//   res.status(200).json({
//     status: 'success',
//     message: 'User updated successfully',
//     data: {
//       user: updatedUser
//     }
//   });
// });

// // Change password
// export const updatePassword = catchAsync(async (req, res, next) => {
//   // Get user from collection
//   const user = await User.findById(req.user.id).select('+password');

//   // Check if current password is correct
//   if (!(await user.comparePassword(req.body.passwordCurrent))) {
//     return next(new AppError('Your current password is incorrect.', 401));
//   }

//   // Update password
//   user.password = req.body.password;
//   await user.save();

//   // Send password change notification (optional - can be removed if not needed)
//   try {
//     // Since your emailService doesn't have a generic sendEmail method,
//     // we'll skip the password change notification for now
//     // You can add a sendNotificationEmail method to your emailService if needed
//     console.log('Password updated for user:', user.email);
//   } catch (error) {
//     console.error('Failed to send password change notification email:', error);
//     // Don't fail password update if notification email fails
//   }

//   // Log user in, send JWT
//   createSendToken(user, 200, res, 'Password updated successfully');
// });