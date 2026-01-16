import { RequestHandler } from "express";
import createHttpError, { InternalServerError } from "http-errors";
import User from "../model/User";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { FRONTEND_URL, JWT_KEY, transporter } from "../config";
import nodemailer from "nodemailer";
export const signupUser: RequestHandler = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return next(createHttpError(422, "Email Already Exist!"));

    const hashedPassword = await bcrypt.hash(password, 8);
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });

    await user.save();

    res.json({ message: "User Created" });
  } catch (error) {
    return next(InternalServerError);
  }
};

export const signinUser: RequestHandler = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return next(createHttpError(404, "User not Found!"));
    if (!user.isUserVerified)
      return next(createHttpError(406, "User not Verified"));

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword)
      return next(createHttpError(401, "Not Valid Password!"));

    const token = jwt.sign(
      {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        userId: user.id,
      },
      JWT_KEY,
      {
        expiresIn: "7d",
      }
    );

    res.cookie("jwt", token);

    res.json({ firstName: user.firstName, lastName: user.lastName, token });
  } catch (error) {
    return next(InternalServerError);
  }
};

export const sendVerificationMail: RequestHandler = async (req, res, next) => {
  const { email }: { email: string } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return next(createHttpError(404, "Email Not Valid!"));

    if (user.isUserVerified)
      return next(createHttpError(406, "User already verified"));

    const encryptedToken = await bcrypt.hash(user._id.toString(), 8);

    const jwtToken = jwt.sign({ userId: user._id }, JWT_KEY, {
      expiresIn: "10m",
    });


    const APP_NAME = "BlockVault";
    await transporter.sendMail({
      from: `"${APP_NAME} Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verify your BlockVault account",
      text: `Verify your BlockVault account: ${FRONTEND_URL}/email-verify/${jwtToken}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; color: #0f172a;">
          <h2>Verify your email address</h2>

          <p>Hello,</p>

          <p>
            Welcome to <strong>BlockVault</strong>.
            To complete your registration and secure your account, please verify your email address.
          </p>

          <div style="margin: 24px 0;">
            <a
              href="${FRONTEND_URL}/email-verify/${jwtToken}"
              style="
                background-color: #1e40af;
                color: #ffffff;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 600;
                display: inline-block;
              "
            >
              Verify Email
            </a>
          </div>

          <p style="font-size: 14px; color: #475569;">
            This verification link will expire in <strong>10 minutes</strong>.
            If you did not create a BlockVault account, no further action is required.
          </p>

          <hr style="margin: 24px 0;" />

          <p style="font-size: 12px; color: #64748b;">
            © ${new Date().getFullYear()} BlockVault. All rights reserved.
          </p>
        </div>
      `,
    });

    await user.updateOne({ $set: { verifyToken: encryptedToken } });

    res.json({ message: "Verification email sent successfully" });
  } catch (error) {
    console.error(error);
    next(InternalServerError);
  }
};


export const verifyUserMail: RequestHandler = async (req, res, next) => {
  const { token }: { token: string } = req.body;

  try {
    const decodedToken: any = jwt.verify(token, JWT_KEY);

    const user = await User.findById(decodedToken.userId);
    if (!user) return next(createHttpError(401, "Token Invalid"));

    await user.updateOne({
      $set: { isUserVerified: true },
      $unset: { verifyToken: 0 },
    });

    res.json({ message: "Email Verified!" });
  } catch (error) {
    return next(createHttpError(401, "Token Invalid"));
  }
};

export const sendForgotPasswordMail: RequestHandler = async (
  req,
  res,
  next
) => {
  const { email }: { email: string } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return next(createHttpError(404, "Email Not Valid!"));

    const encryptedToken = await bcrypt.hash(user._id.toString(), 8);

    const jwtToken = jwt.sign({ userId: user._id }, JWT_KEY, {
      expiresIn: "10m",
    });


    const APP_NAME = "BlockVault";
    await transporter.sendMail({
      from: `"${APP_NAME} Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Reset your BlockVault password",
      text: `Reset your BlockVault password: ${FRONTEND_URL}/forgot-password-verify/${jwtToken}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; color: #0f172a;">
          <h2>Password Reset Request</h2>

          <p>Hello,</p>

          <p>
            We received a request to reset the password for your <strong>BlockVault</strong> account.
            Click the button below to proceed.
          </p>

          <div style="margin: 24px 0;">
            <a
              href="${FRONTEND_URL}/forgot-password-verify/${jwtToken}"
              style="
                background-color: #1e40af;
                color: #ffffff;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 600;
                display: inline-block;
              "
            >
              Reset Password
            </a>
          </div>

          <p style="font-size: 14px; color: #475569;">
            This link will expire in <strong>10 minutes</strong>.
            If you did not request a password reset, you can safely ignore this email.
          </p>

          <hr style="margin: 24px 0;" />

          <p style="font-size: 12px; color: #64748b;">
            © ${new Date().getFullYear()} BlockVault. All rights reserved.
          </p>
        </div>
      `,
    });


        await user.updateOne({ $set: { verifyToken: encryptedToken } });

        res.json({ message: "Password reset email sent" });
      } catch (error) {
        console.error(error);
        next(InternalServerError);
      }
    };

export const verifyForgotMail: RequestHandler = async (req, res, next) => {
  const { token, password }: { token: string; password: string } = req.body;

  try {
    const decodedToken: any = jwt.verify(token, JWT_KEY);

    const user = await User.findById(decodedToken.userId);
    if (!user) return next(createHttpError(401, "Token Invalid"));

    const encryptedPassword = await bcrypt.hash(password, 8);

    await user.updateOne({
      $set: { password: encryptedPassword },
      $unset: { verifyToken: 0 },
    });

    res.json({ message: "Password Changed!" });
  } catch (error) {
    return next(createHttpError(401, "Token Invalid"));
  }
};
