import dotenv from "dotenv";
import nodemailer from "nodemailer";
import SMTPTransport from "nodemailer/lib/smtp-transport";

dotenv.config();

export const DB = process.env.DB!;
export const PORT = parseInt(process.env.PORT!);
export const JWT_KEY = process.env.JWT_KEY!;
export const FRONTEND_URL = process.env.FRONTEND_URL!;

export const transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo> =
  nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER!,
      pass: process.env.EMAIL_PASS!,
    },
  });
