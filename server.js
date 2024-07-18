const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const cron = require("node-cron");
require("dotenv").config(); // Load environment variables

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB Atlas
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

// Note Schema
const noteSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  title: String,
  content: String,
  tags: [String],
  color: String,
  isArchived: Boolean,
  isTrashed: Boolean,
  deletedAt: Date,
  createdAt: { type: Date, default: Date.now },
  reminder: Date,
});

// Models
const User = mongoose.model("User", userSchema);
const Note = mongoose.model("Note", noteSchema);

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).send("Token is required");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
};

// User Registration
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).send("User Registered");
  } catch (err) {
    res.status(400).send("Username already exists");
  }
});

// User Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(400).send("Invalid Username or Password");

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).send("Invalid Username or Password");

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res.status(200).json({ token });
});

// Create Note
app.post("/api/notes", verifyToken, async (req, res) => {
  const { title, content, tags, color, reminder } = req.body;
  const newNote = new Note({
    userId: req.userId,
    title,
    content,
    tags,
    color,
    isArchived: false,
    isTrashed: false,
    reminder,
  });

  await newNote.save();
  res.status(201).send("Note Created");
});

// Get Notes
app.get("/api/notes", verifyToken, async (req, res) => {
  const notes = await Note.find({ userId: req.userId, isTrashed: false });
  res.status(200).json(notes);
});

// Search Notes
app.get("/api/notes/search", verifyToken, async (req, res) => {
  const { query } = req.query;
  const notes = await Note.find({
    userId: req.userId,
    isTrashed: false,
    $or: [
      { title: { $regex: query, $options: "i" } },
      { content: { $regex: query, $options: "i" } },
    ],
  });
  res.status(200).json(notes);
});

// Get Archived Notes
app.get("/api/notes/archived", verifyToken, async (req, res) => {
  const notes = await Note.find({ userId: req.userId, isArchived: true });
  res.status(200).json(notes);
});

// Get Notes by Tag
app.get("/api/notes/tag/:tag", verifyToken, async (req, res) => {
  const { tag } = req.params;
  const notes = await Note.find({
    userId: req.userId,
    tags: tag,
    isTrashed: false,
  });
  res.status(200).json(notes);
});

// Get Trashed Notes
app.get("/api/notes/trashed", verifyToken, async (req, res) => {
  const notes = await Note.find({ userId: req.userId, isTrashed: true });
  res.status(200).json(notes);
});

// Update Note
app.put("/api/notes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, content, tags, color, reminder, isArchived, isTrashed } =
    req.body;

  const note = await Note.findOneAndUpdate(
    { _id: id, userId: req.userId },
    { title, content, tags, color, reminder, isArchived, isTrashed },
    { new: true }
  );

  if (!note) return res.status(404).send("Note not found");
  res.status(200).send("Note Updated");
});

// Move Note to Trash
app.delete("/api/notes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  const note = await Note.findOneAndUpdate(
    { _id: id, userId: req.userId },
    { isTrashed: true, deletedAt: new Date() },
    { new: true }
  );

  if (!note) return res.status(404).send("Note not found");
  res.status(200).send("Note Moved to Trash");
});

// Empty Trash
app.delete("/api/notes/trashed/empty", verifyToken, async (req, res) => {
  await Note.deleteMany({ userId: req.userId, isTrashed: true });
  res.status(200).send("Trash Emptied");
});

// Reminder Notes
app.get("/api/notes/reminders", verifyToken, async (req, res) => {
  const notes = await Note.find({
    userId: req.userId,
    reminder: { $gte: new Date() },
    isTrashed: false,
  });

  res.status(200).json(notes);
});

// Schedule a Job to Delete Notes in Trash for More Than 30 Days
cron.schedule("0 0 * * *", async () => {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  await Note.deleteMany({
    isTrashed: true,
    deletedAt: { $lte: thirtyDaysAgo },
  });
  console.log("Deleted notes in trash for more than 30 days");
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));