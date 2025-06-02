import FoodWaste from '../models/FoodWaste.js';
import User from '../models/User.js';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import dotenv from 'dotenv';

dotenv.config();

// Configure Cloudinary (add to your .env file)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure multer for image upload
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'foodwaste-app',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
    transformation: [{ width: 800, height: 600, crop: 'limit' }]
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Create new food/waste post
const createPost = async (req, res) => {
  try {
    const { 
      type, 
      itemType, 
      quantity, 
      description, 
      location, 
      expirationDate 
    } = req.body;

    // Validate required fields
    if (!type || !itemType || !quantity || !description || !location) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields'
      });
    }

    // Parse location - just a simple string now
    let locationData = location;
    if (!locationData || locationData.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Location is required'
      });
    }

    // Create post data
    const postData = {
      user: req.user.id,
      type,
      itemType,
      quantity: Number(quantity),
      description,
      location: locationData.trim(),
      expirationDate: expirationDate ? new Date(expirationDate) : null
    };

    // Add image if uploaded
    if (req.file) {
      postData.image = {
        url: req.file.path,
        publicId: req.file.filename,
        filename: req.file.originalname
      };
    }

    const newPost = new FoodWaste(postData);
    await newPost.save();

    // Populate user info
    await newPost.populate('user', 'name email');

    res.status(201).json({
      success: true,
      message: `${type === 'food' ? 'Food' : 'Waste'} post created successfully`,
      data: newPost
    });

  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating post',
      error: error.message
    });
  }
};

// Get all posts (with filters)
const getAllPosts = async (req, res) => {
  try {
    const { 
      type, 
      status, 
      location, 
      page = 1, 
      limit = 10 
    } = req.query;

    // Build query
    let query = { isActive: true };
    
    if (type) query.type = type;
    if (status) query.status = status;

    // Simple location-based search using text search
    if (location && location.trim() !== '') {
      query.$text = { $search: location.trim() };
    }

    const posts = await FoodWaste.find(query)
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await FoodWaste.countDocuments(query);

    res.json({
      success: true,
      data: posts,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalPosts: total
      }
    });

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching posts',
      error: error.message
    });
  }
};

// Get single post
const getPost = async (req, res) => {
  try {
    const post = await FoodWaste.findById(req.params.id)
      .populate('user', 'name email')
      .populate('claims.user', 'name email');

    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    res.json({
      success: true,
      data: post
    });

  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching post',
      error: error.message
    });
  }
};

// Get user's posts
const getUserPosts = async (req, res) => {
  try {
    const { page = 1, limit = 10, type, status } = req.query;
    
    let query = { user: req.user.id };
    if (type) query.type = type;
    if (status) query.status = status;

    const posts = await FoodWaste.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await FoodWaste.countDocuments(query);

    res.json({
      success: true,
      data: posts,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalPosts: total
      }
    });

  } catch (error) {
    console.error('Error fetching user posts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user posts',
      error: error.message
    });
  }
};

// Update post
const updatePost = async (req, res) => {
  try {
    const { itemType, quantity, description, location, status, expirationDate } = req.body;
    
    const post = await FoodWaste.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    // Check if user owns the post
    if (post.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this post'
      });
    }

    // Update fields
    if (itemType) post.itemType = itemType;
    if (quantity) post.quantity = Number(quantity);
    if (description) post.description = description;
    if (location) post.location = location.trim();
    if (status) post.status = status;
    if (expirationDate) post.expirationDate = new Date(expirationDate);

    // Update image if uploaded
    if (req.file) {
      // Delete old image from cloudinary if exists
      if (post.image && post.image.publicId) {
        await cloudinary.uploader.destroy(post.image.publicId);
      }
      
      post.image = {
        url: req.file.path,
        publicId: req.file.filename,
        filename: req.file.originalname
      };
    }

    await post.save();
    await post.populate('user', 'name email');

    res.json({
      success: true,
      message: 'Post updated successfully',
      data: post
    });

  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating post',
      error: error.message
    });
  }
};

// Delete post
const deletePost = async (req, res) => {
  try {
    const post = await FoodWaste.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    // Check if user owns the post
    if (post.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this post'
      });
    }

    // Delete image from cloudinary if exists
    if (post.image && post.image.publicId) {
      await cloudinary.uploader.destroy(post.image.publicId);
    }

    await FoodWaste.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Post deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting post',
      error: error.message
    });
  }
};

// Claim a post (for food items)
const claimPost = async (req, res) => {
  try {
    const post = await FoodWaste.findById(req.params.id);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Post not found'
      });
    }

    if (post.user.toString() === req.user.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot claim your own post'
      });
    }

    if (post.status !== 'available') {
      return res.status(400).json({
        success: false,
        message: 'Post is not available for claiming'
      });
    }

    // Check if user already claimed this post
    const existingClaim = post.claims.find(
      claim => claim.user.toString() === req.user.id
    );

    if (existingClaim) {
      return res.status(400).json({
        success: false,
        message: 'You have already claimed this post'
      });
    }

    // Add claim
    post.claims.push({
      user: req.user.id,
      status: 'pending'
    });

    await post.save();
    await post.populate('claims.user', 'name email');

    res.json({
      success: true,
      message: 'Post claimed successfully',
      data: post
    });

  } catch (error) {
    console.error('Error claiming post:', error);
    res.status(500).json({
      success: false,
      message: 'Error claiming post',
      error: error.message
    });
  }
};

export {
  createPost,
  getAllPosts,
  getPost,
  getUserPosts,
  updatePost,
  deletePost,
  claimPost,
  upload
};