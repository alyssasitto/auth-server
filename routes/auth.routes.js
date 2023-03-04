const router = require("express").Router();

const User = require("../models/User.model");

const bcryptjs = require("bcryptjs");
const jsonwebtoken = require("jsonwebtoken");

const isAuthenticated = require("../middlewares/jwt.middleware");

router.post("/signup", (req, res) => {
	const { name, email, password } = req.body;

	if (name === "" || email === "" || password === "") {
		return res
			.status(400)
			.json({ err: "Please enter a name, email, and password" });
	}

	const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
	if (!emailRegex.test(email)) {
		return res.status(400).json({ err: "Please enter a valid email" });
	}

	const passwordRegex = /(?=.*[a-z])(?=.*[A-Z])(?=.{8,})/;
	if (!passwordRegex.test(password)) {
		return res.status(400).json({
			err: "Password must be at least 8 characters long and have at least one uppercase and one lowercase letter",
		});
	}

	User.findOne({ email }).then((user) => {
		if (user) {
			return res.status(400).json({ err: "User already exists" });
		} else {
			const salt = bcryptjs.genSaltSync(10);
			const hashedPassword = bcryptjs.hashSync(password, salt);

			return User.create({
				name: name,
				email: email,
				password: hashedPassword,
			})
				.then(() => {
					return res.status(200).json({ message: "User has been created" });
				})
				.catch(() => {
					return res.status(400).json({ err: "User could not be created" });
				});
		}
	});
});

router.post("/login", (req, res) => {
	const { email, password } = req.body;

	if (email === "" || password === "") {
		return res.status(400).json({ err: "Please enter an email and password" });
	}

	User.findOne({ email })
		.then((user) => {
			if (!user) {
				return res.status(400).json({ err: "Invalid credentials" });
			} else {
				const passwordsMatch = bcryptjs.compareSync(password, user.password);

				if (!passwordsMatch) {
					return res.status(400).json({ err: "Invalid credentials" });
				}

				const payload = {
					name: user.name,
					email: user.email,
					id: user._id,
				};

				const token = jsonwebtoken.sign(payload, process.env.TOKEN_SECRET, {
					algorithm: "HS256",
					expiresIn: "1h",
				});

				res.status(200).json({ token });
			}
		})
		.catch((err) => {
			res.status(400).json({ err: "Something went wrong" });
		});
});

router.get("/verify", isAuthenticated, (req, res) => {
	res.status(200).json(req.user);
});

module.exports = router;
