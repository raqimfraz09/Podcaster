const authMiddleware = require('../middleware/authMiddleware');
const upload = require('../middleware/multer');
const Category = require('../models/category');
const Podcast = require('../models/podcast');
const User = require('../models/user');
const router = require('express').Router();

// Add Podcast..
router.post("/add-podcast", authMiddleware, upload, async (req, res) => {
    try {
        const { title, description, category } = req.body;
        
        if (!req.files || !req.files["frontImage"] || !req.files["audioFile"]) {
            return res.status(400).json({ error: "Both frontImage and audioFile are required." });
        }

        const frontImage = req.files["frontImage"][0].path;
        const audioFile = req.files["audioFile"][0].path;

        if (!title || !description || !category || !frontImage || !audioFile) {
            return res.status(400).json({ error: "All fields are required." });
        }

        const { user } = req;
        let cat = await Category.findOne({ categoryName: category });
        if (!cat) {
            // Auto create category if not exists
            cat = new Category({ categoryName: category });
            await cat.save();
        }

        const catid = cat._id;
        const userid = user._id;
        const newPodcast = new Podcast({
            title,
            description,
            category: catid,
            frontImage,
            audioFile,
            user: userid
        });

        await newPodcast.save();
        await Category.findByIdAndUpdate(catid, {
            $push: { podcasts: newPodcast._id }
        });

        await User.findByIdAndUpdate(userid, {
            $push: { podcasts: newPodcast._id }
        });

        res.status(201).json({
            message: "Podcast added successfully.",
            data: newPodcast
        });
    } catch (error) {
        console.error("Error adding podcast:", error);
        return res.status(500).json({ message: "Failed to add Podcast.", error: error.message });
    }
});

// Get All Podcasts...
router.get("/get-podcasts", async (req, res) => {
    try {
        const podcasts = await Podcast.find()
            .populate("category")
            .populate("user", "username email")
            .sort({ createdAt: -1 });
        return res.status(200).json({ data: podcasts });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error..." });
    }
});

// Get User Podcasts...
router.get("/get-user-podcasts", authMiddleware, async (req, res) => {
    try {
        const { user } = req;
        const userid = user._id;
        const data = await User.findById(userid)
            .populate({
                path: "podcasts",
                populate: [
                    { path: "category" },
                    { path: "user", select: "username email" }
                ]
            })
            .select("-password");

        let userPodcasts = [];
        if (data && data.podcasts) {
            userPodcasts = [...data.podcasts].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        }
        return res.status(200).json({ data: userPodcasts });
    } catch (error) {
        console.error("Error fetching user podcasts:", error);
        return res.status(500).json({ message: "Internal Server Error..." });
    }
});

// Get Podcast by ID...
router.get("/get-podcasts/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const podcast = await Podcast.findById(id)
            .populate("category")
            .populate("user", "username email");
        if (!podcast) {
            return res.status(404).json({ message: "Podcast not found" });
        }
        return res.status(200).json({ data: podcast });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error..." });
    }
});

// Get Podcasts by Category...
router.get("/category/:cat", async (req, res) => {
    try {
        const { cat } = req.params;
        const categories = await Category.find({ categoryName: cat }).populate({
            path: "podcasts",
            populate: [
                { path: "category" },
                { path: "user", select: "username email" }
            ],
        });
        let podcasts = [];
        categories.forEach((category) => {
            if (category.podcasts && category.podcasts.length > 0) {
                podcasts = [...podcasts, ...category.podcasts];
            }
        });

        return res.status(200).json({ data: podcasts });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error..." });
    }
});

// Delete Podcast...
router.delete("/delete-podcast/:id", authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const podcast = await Podcast.findById(id);
        if (!podcast) {
            return res.status(404).json({ message: "Podcast not found" });
        }
        if (podcast.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Unauthorized to delete this podcast" });
        }
        await Podcast.findByIdAndDelete(id);
        await User.findByIdAndUpdate(req.user._id, { $pull: { podcasts: id } });
        if (podcast.category) {
            await Category.findByIdAndUpdate(podcast.category, { $pull: { podcasts: id } });
        }
        return res.status(200).json({ message: "Podcast deleted successfully" });
    } catch (error) {
        console.error("Error deleting podcast:", error);
        return res.status(500).json({ message: "Internal Server Error..." });
    }
});

module.exports = router;