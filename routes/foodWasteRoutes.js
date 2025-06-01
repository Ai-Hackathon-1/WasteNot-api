import express from 'express';
const router = express.Router();
import {
  createPost,
  getAllPosts,
  getPost,
  getUserPosts,
  updatePost,
  deletePost,
  claimPost,
  upload
} from '../controllers/foodWasteController.js';

// Import your existing auth middleware
import {authMiddleware} from '../middlewares/authMiddleware.js';

// Public routes

// all post with filters
router.get('/', getAllPosts); 
// get post by id
router.get('/:id', getPost); 

// Protected routes (require authentication)
router.use(authMiddleware); // Apply auth middleware to all routes below

// User post management
router.post('/', upload.single('image'), createPost); // Create new post
router.get('/user/posts', getUserPosts); // Get current user's posts
router.put('/:id', upload.single('image'), updatePost); // Update post
router.delete('/:id', deletePost); // Delete post

// Post interaction
router.post('/:id/claim', claimPost); // Claim a post

export default router;