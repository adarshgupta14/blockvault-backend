import express from "express";
import createHttpError from "http-errors";
import userRoute from "./routes/userRoutes";
import mongoose from "mongoose";
import { DB, PORT } from "./config";
import { errorHandler } from "./middleware/errorHanlder";
import passport from "passport";
import kPassport from "./middleware/passport";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

const allowedOrigins = [
  "http://localhost:5173",
  "https://blockvaultcrypto.vercel.app"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true
  })
);

app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

app.use(passport.initialize());
kPassport(passport);

app.use("/user", userRoute);

app.use(() => {
  throw createHttpError(404, "Route not found");
});

app.use(errorHandler);

mongoose
  .connect(DB)
  .then(() => {
    console.log("Connected to db");
    app.listen(PORT, () => {
      console.log(`Listening on PORT ${PORT}`);
    });
  })
  .catch(() => {
    throw createHttpError(501, "Unable to connect database");
  });
