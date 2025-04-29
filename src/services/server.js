// server/server.js
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import User from './models/user.js'; // Note the .js extension is required in ES modules

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001; // Port is mainly for local dev

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected successfully');
    console.log(`Connected to database: '${mongoose.connection.name}'`);
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Signup Route (with Hashing)
app.post('/api/auth/signup', async (req, res) => {
  console.log('--- SIGNUP ROUTE HIT ---');
  console.log('Request Body:', req.body);
  try {
    const { email, password, name } = req.body;
    console.log(`Received signup request for: ${email}`);

    if (!email || !password) {
      console.log('Validation failed: Email or password missing');
      return res.status(400).json({ message: 'Email and password are required' });
    }
    // Add password length validation if needed

    console.log(`Checking if user exists: ${email}`);
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log(`User already exists: ${email}`);
      return res.status(409).json({ message: 'User already exists with this email' });
    }
    console.log(`User does not exist, proceeding to create: ${email}`);

    // --- HASH THE PASSWORD ---
    const saltRounds = 10; // Or more
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log(`Password hashed for: ${email}`);
    // --- END HASHING ---

    // Store the hashed password
    const newUser = new User({ email, password: hashedPassword, name });
    await newUser.save();
    console.log(`User saved successfully: ${email}, ID: ${newUser._id}`);

    // Don't send password back, even hashed
    const userResponse = { id: newUser._id, email: newUser.email, name: newUser.name };
    res.status(201).json({ message: 'User created successfully', user: userResponse });
    console.log(`Signup successful for: ${email}`);
  } catch (error) {
    console.error("!!! Signup Server Error !!!");
    console.error("Error Details:", error);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
       console.log(`Password mismatch for: ${email}`);
       return res.status(401).json({ message: 'Invalid email or password' });
    }

    const userResponse = { id: user._id, email: user.email, name: user.name };
    res.status(200).json({ message: 'Login successful', user: userResponse });
    console.log(`Login successful for: ${email}`);
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

if (process.env.NODE_ENV !== 'production') { 
  app.listen(PORT, () => {
    console.log(`Server running for local development on http://localhost:${PORT}`);
  });
}

export default app;