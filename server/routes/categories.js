const router = require('express').Router();
const Cat = require('../models/category');

const DEFAULT_CATEGORIES = [
    "Tech & AI",
    "Business & Startups",
    "Comedy & Entertainment",
    "Health & Wellness",
    "Education & Science",
    "News & Politics",
    "Music & Culture",
    "Storytelling & Fiction"
];

// Add Categories...
router.post("/add-category", async (req, res) => {
    try {
        const { categoryName } = req.body;
        if (!categoryName || !categoryName.trim()) {
            return res.status(400).json({ error: "Category name is required" });
        }
        const existing = await Cat.findOne({ categoryName: categoryName.trim() });
        if (existing) {
            return res.status(200).json({ message: "Category already exists", data: existing });
        }
        const cat = new Cat({ categoryName: categoryName.trim() });
        await cat.save();
        return res.status(200).json({ message: "Category added", data: cat });
    } catch (error) {
        console.error("Error adding category:", error);
        return res.status(500).json({ message: "Error adding category" });
    }
});

// Get all categories (and seed defaults if collection is empty)
router.get("/get-categories", async (req, res) => {
    try {
        let categories = await Cat.find().sort({ categoryName: 1 });
        if (categories.length === 0) {
            // Seed defaults
            for (const name of DEFAULT_CATEGORIES) {
                await Cat.findOneAndUpdate(
                    { categoryName: name },
                    { categoryName: name },
                    { upsert: true, new: true }
                );
            }
            categories = await Cat.find().sort({ categoryName: 1 });
        }
        return res.status(200).json({ data: categories });
    } catch (error) {
        console.error("Error fetching categories:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = router;