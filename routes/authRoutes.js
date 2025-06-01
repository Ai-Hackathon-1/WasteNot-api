import express from 'express';
import {
  register,
  registerAdmin,
  login,
  logout,
  protect,
  verifyEmail,
  getMe,
  updateMe,
  updatePassword
} from '../controllers/authController.js';
import {
  validateUserRegistration,
  validateAdminRegistration,
  validateLogin,
  validateUpdateProfile,
  validatePasswordUpdate
} from '../middlewares/validation.js';

const router = express.Router();

// Public routes
router.post('/register', validateUserRegistration, register);
router.post('/login', validateLogin, login);
router.get('/logout', logout);
router.patch('/verify-email/:token', verifyEmail);

// Admin registration (protected with secret key)
router.post('/register-admin', validateAdminRegistration, registerAdmin);

// Protected routes (require authentication)
router.use(protect); // All routes after this middleware are protected

router.get('/me', getMe);
router.patch('/update-me', validateUpdateProfile, updateMe);
router.patch('/update-password', validatePasswordUpdate, updatePassword);

export default router;