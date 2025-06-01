import User from '../models/User.js';
import AppError from '../utils/appError.js';
import catchAsync from '../utils/catchAsync.js';

// Get all users (Admin only)
export const getAllUsers = catchAsync(async (req, res, next) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  
  // Build filter object
  const filter = {};
  if (req.query.role) filter.role = req.query.role;
  if (req.query.isActive !== undefined) filter.isActive = req.query.isActive === 'true';
  if (req.query.isVerified !== undefined) filter.isVerified = req.query.isVerified === 'true';
  
  // Search functionality
  if (req.query.search) {
    const searchRegex = new RegExp(req.query.search, 'i');
    filter.$or = [
      { firstName: searchRegex },
      { lastName: searchRegex },
      { email: searchRegex },
      { 'organization.name': searchRegex }
    ];
  }

  const users = await User.find(filter)
    .select('-password')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

  const totalUsers = await User.countDocuments(filter);
  const totalPages = Math.ceil(totalUsers / limit);

  res.status(200).json({
    status: 'success',
    results: users.length,
    pagination: {
      currentPage: page,
      totalPages,
      totalUsers,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1
    },
    data: {
      users
    }
  });
});

// Get user by ID (Admin only)
export const getUserById = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id).select('-password');
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

// Update user (Admin only)
export const updateUser = catchAsync(async (req, res, next) => {
  // Prevent password updates through this route
  if (req.body.password) {
    return next(new AppError('This route is not for password updates', 400));
  }

  // Prevent role changes to admin unless current user is admin
  if (req.body.role === 'admin' && !req.user.isAdmin()) {
    return next(new AppError('Only admin can create other admin users', 403));
  }

  const user = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true
  }).select('-password');

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    message: 'User updated successfully',
    data: {
      user
    }
  });
});

// Deactivate user (Admin only)
export const deactivateUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  // Prevent admin from deactivating themselves
  if (user._id.toString() === req.user._id.toString()) {
    return next(new AppError('You cannot deactivate your own account', 400));
  }

  // Prevent deactivating other admins
  if (user.role === 'admin') {
    return next(new AppError('Cannot deactivate admin users', 400));
  }

  user.isActive = false;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'User deactivated successfully'
  });
});

// Activate user (Admin only)
export const activateUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  user.isActive = true;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'User activated successfully'
  });
});

// Delete user (Admin only)
export const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  // Prevent admin from deleting themselves
  if (user._id.toString() === req.user._id.toString()) {
    return next(new AppError('You cannot delete your own account', 400));
  }

  // Prevent deleting other admins
  if (user.role === 'admin') {
    return next(new AppError('Cannot delete admin users', 400));
  }

  await User.findByIdAndDelete(req.params.id);

  res.status(204).json({
    status: 'success',
    data: null
  });
});

// Get user statistics (Admin only)
export const getUserStats = catchAsync(async (req, res, next) => {
  const stats = await User.aggregate([
    {
      $group: {
        _id: '$role',
        count: { $sum: 1 },
        active: {
          $sum: {
            $cond: [{ $eq: ['$isActive', true] }, 1, 0]
          }
        },
        verified: {
          $sum: {
            $cond: [{ $eq: ['$isVerified', true] }, 1, 0]
          }
        }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);

  const totalUsers = await User.countDocuments();
  const activeUsers = await User.countDocuments({ isActive: true });
  const verifiedUsers = await User.countDocuments({ isVerified: true });
  const recentUsers = await User.countDocuments({
    createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
  });

  res.status(200).json({
    status: 'success',
    data: {
      overview: {
        totalUsers,
        activeUsers,
        verifiedUsers,
        recentUsers
      },
      roleStats: stats
    }
  });
});

// Verify user email (Admin only)
export const verifyUserEmail = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  user.isVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'User email verified successfully'
  });
});

// Get users by role
export const getUsersByRole = catchAsync(async (req, res, next) => {
  const { role } = req.params;
  
  const validRoles = ['admin', 'restaurant_owner', 'food_bank', 'volunteer', 'donor'];
  if (!validRoles.includes(role)) {
    return next(new AppError('Invalid role specified', 400));
  }

  const users = await User.findByRole(role).select('-password');

  res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users
    }
  });
});