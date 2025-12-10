// Backend: server.js (Node.js + Express + MongoDB)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// ----------------- MongoDB Connection -----------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB:", err));

// ----------------- Schemas & Models -------------------
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  phone: String,
  bookings: [
    {
      busName: String,
      seatNumber: Number,
      date: String,
    },
  ],
});

const User = mongoose.model("User", UserSchema);

const BookingSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  busName: String,
  seatNumber: Number,
  date: String,
});

const Booking = mongoose.model("Booking", BookingSchema);

const MessageSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
  date: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", MessageSchema);

// ----------------- Middleware -------------------
app.use(cors());

// parse JSON bodies
app.use(express.json());

// parse form-urlencoded bodies (optional but safe)
app.use(express.urlencoded({ extended: true }));

// serve static files from "public" folder
app.use(express.static(path.join(__dirname, "public")));

// ----------------- Auth Middleware -------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // user.email will be available
    next();
  });
}

// ----------------- Routes -------------------

// Register User (SIGNUP)
app.post("/api/signup", async (req, res) => {
  console.log("Signup body:", req.body); // debug log

  // avoid crash when body is undefined
  const { name, email, password, phone } = req.body || {};

  // Basic validation
  if (!name || !email || !password || !phone) {
    return res
      .status(400)
      .json({ error: "All fields (name, email, password, phone) are required" });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({ name, email, password: hashedPassword, phone });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error during sign-up:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login User (SIGNIN)
app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Error logging in" });
  }
});

// Book a Seat
app.post("/api/book-seat", authenticateToken, async (req, res) => {
  const { busName, seatNumber, date } = req.body || {};
  const email = req.user.email; // Use email from token

  try {
    // Validate input
    if (!busName || !seatNumber || !date) {
      return res
        .status(400)
        .json({ error: "Bus name, seat number, and date are required." });
    }

    // Check if a booking already exists for the same bus, seat, and date
    const existingBooking = await Booking.findOne({ busName, seatNumber, date });
    if (existingBooking) {
      return res
        .status(400)
        .json({ error: "Seat already booked for this bus and date." });
    }

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if user already has a booking for the same bus and date
    const userExistingBooking = await Booking.findOne({
      user: user._id,
      busName,
      date,
    });
    if (userExistingBooking) {
      return res
        .status(400)
        .json({ error: "You already have a booking for this bus on this date." });
    }

    // Create a new booking document
    const booking = new Booking({ user: user._id, busName, seatNumber, date });
    await booking.save();

    // Also add to user's bookings array for backward compatibility
    user.bookings.push({ busName, seatNumber, date });
    await user.save();

    res.status(200).json({
      message: "Seat booked successfully! 🎉",
      booking: {
        busName,
        seatNumber,
        date,
        userEmail: email,
      },
    });
  } catch (error) {
    console.error("Error during booking:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Contact / Messages
app.post("/api/messages", async (req, res) => {
  const { name, email, message } = req.body || {};
  if (!message || !message.trim()) {
    return res.status(400).json({ error: "Message cannot be empty" });
  }
  try {
    const newMessage = new Message({ name, email, message });
    await newMessage.save();
    res.status(201).json({ message: "Message received and stored!" });
  } catch (error) {
    console.error("Error saving message:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get My Bookings
app.get("/api/my-bookings", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const bookings = await Booking.find({ user: user._id });
    res.json({ bookings });
  } catch (error) {
    console.error("Error fetching bookings:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Serve Frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
