require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const CryptoJS = require("crypto-js");
const SECRET_KEY = "hellokitty";


const app = express();
app.use(express.json());
app.use(cookieParser());

// Enable CORS with credentials
app.use(cors({
  origin: "http://localhost:3000", // Frontend URL
  credentials: true, // Allow cookies
}));

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/auth_jwt", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User model
const User = mongoose.model("User", new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}));

const decryptPassword = (encryptedPassword) => {
  const bytes = CryptoJS.AES.decrypt(encryptedPassword, SECRET_KEY);
  const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);
  return decryptedPassword;
};
// Signup Route
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: "User already exists" });
  const decryptedPassword = decryptPassword(password);
  if (!decryptedPassword) return res.status(400).json({ message: "Invalid password" });
  const hashedPassword = await bcrypt.hash(decryptedPassword, 10); // Hash the password
  const user = new User({ email, password: hashedPassword });
  await user.save();
  // Create token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  // Store token in HTTP-only cookie
  res.cookie("token", token, { httpOnly: true, secure: false, sameSite: "strict" });
  res.json({ message: "User registered successfully", user });
});



app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Invalid email or password 1" });
  const decryptedPassword = decryptPassword(password);
  if (!decryptedPassword) return res.status(400).json({ message: "Invalid email or password 2" });
  console.log("decryptedPassword", decryptedPassword)
  const isMatch = await bcrypt.compare(decryptedPassword, user.password);
  console.log("isMatch", isMatch)
  if (!isMatch) return res.status(400).json({ message: "Invalid email or password 3" });
  // Generate JWT token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  // Store token in HTTP-only cookie
  res.cookie("token", token, { httpOnly: true, secure: false, sameSite: "strict" });
  res.json({ message: "Login successful" });
});

// Logout Route (Clear Cookie)
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

// Middleware to verify JWT from cookies
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

// Protected Route
app.get("/protected", authMiddleware, (req, res) => {
  res.json({ message: "Welcome to the protected route", user: req.user });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
