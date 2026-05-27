const router = require('express').Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../middleware/authMiddleware');


// User Sign Up Route
router.post("/sign-up", async (req, res) => {

    try{
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: "All fields are required: " });
        }
        if(username.length < 5){
            return res.status(400).json({ error: "Username must be at least 5 characters long." });
        }
        if(password.length < 8){
            return res.status(400).json({ error: "Password must be at least 8 characters long." });
        }


        // Checks User exist or not
        const existingEmail = await User.findOne({ email: email });
        const existingUsername = await User.findOne({ username: username });
        if (existingEmail || existingUsername) {
            return res.status(400).json({ error: "User already exists." });
        }


        // Hashing the password
        const salt = await bcrypt.genSalt(10);
        const hashedPass = await bcrypt.hash(password, salt);

        const newUser = new User({
            username: username,
            email: email,
            password: hashedPass
        });
        await newUser.save();
        return res.status(201).json({ message: "User created successfully." });

    } catch (error) {
        console.log(error);
        res.status(500).json({ error });
    }
});

// User Login Route
router.post("/sign-in", async (req, res) => {
    try{
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "All fields are required." });
        }

        // Check if user exists
        const existingUser = await User.findOne({ email: email });
        if (!existingUser) {
            return res.status(400).json({ error: "Invalid Credentials..." });
        }
        // Check password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid Credentials..." });
        }

        // Generate JWT token
        const token = jwt.sign({id:existingUser._id, email: existingUser.email},
             process.env.JWT_SECRET,
              { expiresIn: "30d" }
            );


        res.cookie("podcasterUserToken", token, {
            httpOnly: true,
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            secure: process.env.NODE_ENV === "production", // Set to true in production
            sameSite: "None",
        });

        return res.status(200).json({
            id: existingUser._id,
            username: existingUser.username, 
            email: email,
            message: "User logged in successfully.",
        });


       
    } catch (error){
        console.log(error);
        res.status(500).json({ error });
    }
});

// User Logout Route

router.post("/logout",  async (req, res) => {
    res.clearCookie("podcasterUserToken", {
        httpOnly: true,
    });
    res.json({ message: "User logged out successfully." });

});

// Check Cookie present or not
router.get("/check-cookie",  async (req, res) => {
    const token = req.cookies.podcasterUserToken;
    if (!token) {
        res.status(200).json({ message: true});
    }
    res.status(200).json({ message: false});

});


// Route to fetch user details...
router.get("/user-details",authMiddleware,  async (req, res) => {
    try{
    const { email } = req.user;
    const existingUser = await User.findOne({ email: email }).select("-password");
    return res.status(200).json({
        user: existingUser,
    })        
    } catch (error){
        console.log(error);
        res.status(500).json({ error });
    }
    

});


module.exports = router;