const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();
require("./db/conn");

const router = require("./routes/router");

const app = express();
const port = 5050;

app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use(router);

app.get("/", (req, res) => {
  res.send("Document server working");
});

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
