const express = require("express");
const app = express();
const PORT = 8081;
const dotenv = require("dotenv").config();
const cors = require("cors");

//DB CONNECTION
const connection = require("./db/connection");
connection();

//ALL ROUTERS
const propertyRouter = require("./routes/property");
const userRouter = require("./routes/user");

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }))






app.use("/", propertyRouter);
app.use("/", userRouter);
app.listen(PORT || process.env.PORT, () => { console.log(`server started at PORT ${PORT}`) })