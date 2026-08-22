const jwt = require("jsonwebtoken");
const User = require('../models/user');

const authMiddleware = async (req, res, next) => {
    const token = req.cookies.podcasterUserToken;
    if (!token) {
        return res.status(401).json({ message: "Authentication required. Please log in." });
    }
    try {
        const jwtSecret = process.env.JWT_SECRET || 'podcaster_super_secret_jwt_key_2026_modern_light_theme';
        const decode = jwt.verify(token, jwtSecret);
        const user = await User.findById(decode.id);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        req.user = user;
        next();
    } catch (error) {
        console.error("Auth middleware error:", error.message);
        return res.status(401).json({ message: "Invalid or expired token. Please log in again." });
    }
};

module.exports = authMiddleware;