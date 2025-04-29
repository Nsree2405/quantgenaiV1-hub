import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
    // In a real app, NEVER store plain text passwords. Use bcrypt.
  },
  // Add any other user fields you might need, e.g., name
  name: {
    type: String,
    required: false, // Make optional or required as needed
  }
});

const User = mongoose.model('User', userSchema);

export default User;