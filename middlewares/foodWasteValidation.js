import { body, validationResult } from 'express-validator';

// Validation rules for creating/updating posts
const validatePost = [
  body('type')
    .isIn(['food', 'waste'])
    .withMessage('Type must be either "food" or "waste"'),
  
  body('itemType')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Item type must be between 2 and 100 characters'),
  
  body('quantity')
    .isFloat({ min: 0.1 })
    .withMessage('Quantity must be a positive number (minimum 0.1)'),
  
  body('description')
    .trim()
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  
  body('location')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Location must be between 5 and 200 characters'),
  
  body('expirationDate')
    .optional()
    .isISO8601()
    .withMessage('Expiration date must be a valid date')
    .custom((value) => {
      if (value && new Date(value) <= new Date()) {
        throw new Error('Expiration date must be in the future');
      }
      return true;
    })
];

// Validation rules for updating posts
const validateUpdatePost = [
  body('itemType')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Item type must be between 2 and 100 characters'),
  
  body('quantity')
    .optional()
    .isFloat({ min: 0.1 })
    .withMessage('Quantity must be a positive number (minimum 0.1)'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ min: 10, max: 500 })
    .withMessage('Description must be between 10 and 500 characters'),
  
  body('location')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Location must be between 5 and 200 characters'),
  
  body('status')
    .optional()
    .isIn(['available', 'claimed', 'expired', 'removed'])
    .withMessage('Status must be one of: available, claimed, expired, removed'),
  
  body('expirationDate')
    .optional()
    .isISO8601()
    .withMessage('Expiration date must be a valid date')
];

// Middleware to handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(error => ({
        field: error.path,
        message: error.msg,
        value: error.value
      }))
    });
  }
  
  next();
};

export {
  validatePost,
  validateUpdatePost,
  handleValidationErrors
};