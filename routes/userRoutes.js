import express from 'express';
import {
  getAllUsers,
  getUserById,
  updateUser,
  deactivateUser,
  activateUser,
  deleteUser,
  getUserStats,
  verifyUserEmail,
  getUsersByRole
} from '../controllers/userController.js';
import { protect, adminOnly } from '../controllers/authController.js';
import { validateUpdateProfile } from '../middlewares/validation.js';

const router = express.Router();

// All routes are protected and require admin access
router.use(protect);

// Public routes for authenticated users
router.get('/role/:role', getUsersByRole);

// Admin only routes
router.use(adminOnly);

router.get('/', getAllUsers);
router.get('/stats', getUserStats);
router.get('/:id', getUserById);
router.patch('/:id', validateUpdateProfile, updateUser);
router.patch('/:id/deactivate', deactivateUser);
router.patch('/:id/activate', activateUser);
router.patch('/:id/verify-email', verifyUserEmail);
router.delete('/:id', deleteUser);

export default router;