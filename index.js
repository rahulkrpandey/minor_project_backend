const express = require("express");
const app = express();
const mongoose = require("mongoose");
require("dotenv").config();
const bcrypt = require("bcrypt");
const User = require("./models/User");
const cors = require("cors");
const jwt = require("jsonwebtoken");

app.use(express.json());
app.use(cors());

mongoose.connect(process.env.DB_URI, {});

const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

app.use((req, res, next) => {
  res.status(400);
  next();
});

const validatePassword = async (req, res, next) => {
  try {
    const { email, password } = req.body.data;
    const user = await User.findOne({
      email,
    });

    if (!user) {
      throw new Error("User not found");
    }

    const cmp = await bcrypt.compare(password, user.password);
    if (!cmp) {
      throw new Error("Password is not correct");
    }

    next();
  } catch (err) {
    next(err);
  }
};

const validateJwt = (req, res, next) => {
  try {
    const token = req.headers.authorization.split("Bearer ")[1];
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    next(err);
  }
};


const addEmail = (req, res, next) => {
  try {
    const token = req.headers.authorization.split("Bearer ")[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    console.log(payload);
    req.body.data.email = payload.email;
    next();
  } catch (err) {
    next(err);
  }
};

app.post("/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body.data;
    const user = new User();
    const pass = await bcrypt.hash(password, 10);
    user.email = email;
    user.password = pass;
    await user.save();
    res.status(200).send("user created");
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.post("/login", validatePassword, async (req, res, next) => {
  try {
    const token = jwt.sign(req.body.data, process.env.JWT_SECRET, {
      algorithm: "HS256",
    });

    res.status(200).send({
      token,
    });
  } catch (err) {
    next(err);
  }
});

app.post("/jobs", validateJwt, addEmail, async (req, res, next) => {
  try {
    const { email, job } = req.body.data;
    const user = await User.findOne({
      email,
    });

    if (!user) {
      throw new Error("User not exist");
    }
    user.jobs.push(job);
    await user.save();
    res.status(200).send("Job Added");
  } catch (err) {
    console.log(err);
    next(err);
  }
});

app.get("/jobs/:email", validateJwt, async (req, res, next) => {
  try {
    const email = req.params.email;
    const user = await User.findOne({
        email
    });

    res.status(200).json(user.jobs);
  } catch (err) {
    next(err);
  }
});

app.put("/jobs", validateJwt, addEmail, async (req, res, next) => {
  try {
    const { email, job } = req.body.data;
    const user = await User.findOne({
      email,
    });

    if (!user) {
      throw new Error("User not exist");
    }

    user.jobs = user.jobs.map((item) => {
      if (item.id === job.id) {
        return job;
      }

      return item;
    });

    await user.save();
    res.status(200).json("Job updated");
  } catch (err) {
    next(err);
  }
});

app.post("/jobs/:jid", validateJwt, addEmail, async (req, res, next) => {
  try {
    const { email } = req.body.data;
    const jid = req.params.jid;
    const user = await User.findOne({
      email,
    });

    if (!user) {
      throw new Error("user not found");
    }

    user.jobs = user.jobs.filter((item) => {
      return item.id !== jid;
    });

    await user.save();
    res.status(200).json("Job Deleted");
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  res.send(err.message);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
