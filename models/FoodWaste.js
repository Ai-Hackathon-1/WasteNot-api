import mongoose from 'mongoose';

const foodWasteSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['food', 'waste'],
    required: true
  },
  itemType: {
    type: String,
    required: true,
    trim: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 0.1
  },
  unit: {
    type: String,
    default: 'kg',
    enum: ['kg', 'g', 'lbs']
  },
  description: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500
  },
  location: {
    type: String,
    required: true,
    trim: true
  },
  image: {
    url: String,
    publicId: String, // for cloudinary
    filename: String
  },
  status: {
    type: String,
    enum: ['available', 'claimed', 'expired', 'removed'],
    default: 'available'
  },
  expirationDate: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  claims: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    claimedAt: {
      type: Date,
      default: Date.now
    },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'completed'],
      default: 'pending'
    }
  }]
}, {
  timestamps: true
});

// Index for location-based queries (text search)
foodWasteSchema.index({ location: 'text' });

// Index for type and status
foodWasteSchema.index({ type: 1, status: 1 });

export default mongoose.model('FoodWaste', foodWasteSchema);