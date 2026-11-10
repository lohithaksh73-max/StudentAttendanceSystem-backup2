
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const Student = require("./models/student");
const User = require("./models/user");
const Attendance = require("./models/Attendance");

const app = express();

app.use(cors());
app.use(express.json());

function authenticateToken(req, res, next) {
    const authorization = req.headers.authorization || "";
    const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        console.error("JWT_SECRET is missing from .env");
        return res.status(500).json({
            message: "Server authentication configuration error."
        });
    }

    if (!token) {
        return res.status(401).json({ message: "Authentication required." });
    }

    try {
        req.auth = jwt.verify(token, secret);
        next();
    } catch {
        return res.status(401).json({ message: "Invalid or expired session." });
    }
}

// Home
app.get("/", (req, res) => {
    res.send("Student Attendance API is running!");
});

// Test connection
app.get("/api/test", (req, res) => {
    res.json({
        message: "Backend and MongoDB connected successfully!"
    });
});

// REGISTER
app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "Please enter name, email and password."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must contain at least 6 characters."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await User.findOne({
            email: normalizedEmail
        });

        if (existingUser) {
            return res.status(409).json({
                message: "This email is already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            password: hashedPassword,
            role: "teacher"
        });

        res.status(201).json({
            message: "Registration successful!",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Registration error:", error.message);
        res.status(500).json({
            message: "Registration failed. Please try again."
        });
    }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Please enter email and password."
            });
        }

        const user = await User.findOne({
            email: email.trim().toLowerCase()
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        const secret = process.env.JWT_SECRET;

        if (!secret) {
            console.error("JWT_SECRET is missing from .env");
            return res.status(500).json({
                message: "Server authentication configuration error."
            });
        }

        const token = jwt.sign(
            {
                userId: user._id.toString(),
                role: user.role
            },
            secret,
            { expiresIn: "1d" }
        );

        res.json({
            message: "Login successful!",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({
            message: "Login failed. Please try again."
        });
    }
});

app.use("/api/students", authenticateToken);
app.use("/api/attendance", authenticateToken);

// GET ALL STUDENTS
app.get("/api/students", async (req, res) => {
    try {
        const students = await Student.find().sort({ createdAt: -1 });
        res.json(students);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// GET ATTENDANCE FOR A DATE
app.get("/api/attendance", async (req, res) => {
    try {
        const { date } = req.query;

        if (typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).json({
                message: "Please provide a valid attendance date."
            });
        }

        const records = await Attendance.find({ date })
            .populate("student", "name rollNumber")
            .sort({ createdAt: -1 });
        res.json(records);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// CREATE OR UPDATE ATTENDANCE
app.put("/api/attendance/:studentId", async (req, res) => {
    try {
        const { date, status } = req.body;

        if (typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).json({
                message: "Please provide a valid attendance date."
            });
        }

        if (!["Present", "Absent", "Late"].includes(status)) {
            return res.status(400).json({
                message: "Attendance status must be Present, Absent, or Late."
            });
        }

        const record = await Attendance.findOneAndUpdate(
            { student: req.params.studentId, date },
            { status },
            { new: true, upsert: true, runValidators: true }
        ).populate("student", "name rollNumber");

        res.json(record);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// SEARCH STUDENTS
app.get("/api/students/search", async (req, res) => {
    try {
        const search = req.query.q || "";

        const students = await Student.find({
            $or: [
                { name: { $regex: search, $options: "i" } },
                { rollNumber: { $regex: search, $options: "i" } }
            ]
        });

        res.json(students);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// ADD STUDENT
app.post("/api/students", async (req, res) => {
    try {
        const { name, rollNumber, course, year } = req.body;

        if (!name || !rollNumber || !course || !year) {
            return res.status(400).json({
                message: "Please provide all student details."
            });
        }

        const student = await Student.create({
            name,
            rollNumber,
            course,
            year: Number(year)
        });

        res.status(201).json({
            message: "Student added successfully!",
            student
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                message: "Roll number already exists."
            });
        }

        res.status(400).json({ message: error.message });
    }
});

// DELETE STUDENT
app.delete("/api/students/:id", async (req, res) => {
    try {
        const student = await Student.findByIdAndDelete(req.params.id);

        if (!student) {
            return res.status(404).json({
                message: "Student not found."
            });
        }

        res.json({ message: "Student deleted successfully!" });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// START SERVER
const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log("MongoDB connected successfully!");
        await Student.syncIndexes();

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.error("MongoDB connection failed:", error.message);
    });
