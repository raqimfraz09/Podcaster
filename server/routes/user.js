const router = require('express').Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../middleware/authMiddleware');

// User Sign Up Route
router.post("/sign-up", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: "All fields are required." });
        }
        if (username.length < 3) {
            return res.status(400).json({ error: "Username must be at least 3 characters long." });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "Password must be at least 6 characters long." });
        }

        // Checks User exist or not
        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        const existingUsername = await User.findOne({ username: username });
        if (existingEmail || existingUsername) {
            return res.status(400).json({ error: "User with this email or username already exists." });
        }

        // Hashing the password
        const salt = await bcrypt.genSalt(10);
        const hashedPass = await bcrypt.hash(password, salt);

        const newUser = new User({
            username: username,
            email: email.toLowerCase(),
            password: hashedPass
        });
        await newUser.save();
        return res.status(201).json({ message: "User created successfully." });

    } catch (error) {
        console.error("Sign up error:", error);
        res.status(500).json({ error: "Failed to create account. Please try again." });
    }
});

// User Login Route
router.post("/sign-in", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "All fields are required." });
        }

        // Check if user exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (!existingUser) {
            return res.status(400).json({ error: "Invalid email or password." });
        }
        // Check password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid email or password." });
        }

        // Generate JWT token
        const jwtSecret = process.env.JWT_SECRET || 'podcaster_super_secret_jwt_key_2026_modern_light_theme';
        const token = jwt.sign(
            { id: existingUser._id, email: existingUser.email },
            jwtSecret,
            { expiresIn: "30d" }
        );

        res.cookie("podcasterUserToken", token, {
            httpOnly: true,
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            path: "/"
        });

        return res.status(200).json({
            id: existingUser._id,
            username: existingUser.username,
            email: existingUser.email,
            message: "User logged in successfully.",
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Failed to sign in. Please try again." });
    }
});

// User Logout Route
router.post("/logout", async (req, res) => {
    res.clearCookie("podcasterUserToken", {
        httpOnly: true,
        path: "/",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        secure: process.env.NODE_ENV === "production"
    });
    return res.status(200).json({ message: "User logged out successfully." });
});

// Check Cookie present or not
router.get("/check-cookie", async (req, res) => {
    const token = req.cookies.podcasterUserToken;
    if (!token) {
        return res.status(200).json({ message: false });
    }
    try {
        const jwtSecret = process.env.JWT_SECRET || 'podcaster_super_secret_jwt_key_2026_modern_light_theme';
        jwt.verify(token, jwtSecret);
        return res.status(200).json({ message: true });
    } catch (e) {
        return res.status(200).json({ message: false });
    }
});

// Route to fetch user details...
router.get("/user-details", authMiddleware, async (req, res) => {
    try {
        const { email } = req.user;
        const existingUser = await User.findOne({ email: email }).select("-password");
        if (!existingUser) {
            return res.status(404).json({ message: "User not found" });
        }
        return res.status(200).json({
            user: existingUser,
        });
    } catch (error) {
        console.error("Fetch user details error:", error);
        res.status(500).json({ error: "Failed to fetch user details" });
    }
});

module.exports = router;