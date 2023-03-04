const express = require("express");

const logger = require("morgan");

const cors = require("cors");

module.exports = (app) => {
	app.use(
		cors({
			origin: "http://localhost:3000",
		})
	);

	// Logs requests
	app.use(logger("dev"));

	// parses incoming requests
	app.use(express.json());
};
