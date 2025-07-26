import express, { Request, Response } from "express";
import { config } from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcryptjs from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
config();
const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

const PORT = process.env.PORT!;
const prisma = new PrismaClient();

// Sign up route
app.post("/signup", async (req: Request, res: Response): Promise<any> => {
  const { username, email, password } = req.body;

  // checking if any feild from  username , email , password is missing

  if (!username || !email || !password) {
    return res.status(404).json({ success: false, messsage: "Invalid Input" });
  }
  try {
    // checking that the email is unique

    const isUserExist = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (isUserExist) {
      return res.json({
        success: false,
        message: "Email is already taken please use differnt email",
      });
    }
    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashPassword,
      },
    });

    return res.json({
      success: true,
      message: "User created successfully",
      user: newUser,
    });
  } catch (e: any) {
    console.log(`Error while signup ${e.message}`);
    return res.json({
      success: false,
      message: "Error while singup",
      error: e.message,
    });
  }
});

// sign in route

app.post("/signin", async (req: Request, res: Response): Promise<any> => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Please provide valid credentials",
    });
  }
  // checking that the email is user provided is exist is database if email is not found in database then user is not valid and else user is valid user
  const isUserExist = await prisma.user.findFirst({
    where: {
      email,
    },
  });
  // If user is not found in database then return response user not found
  if (!isUserExist) {
    return res.json({ success: false, message: "User not found" });
  }
  // If user found in database then check the password is correct or not

  const isValidPassword = await bcryptjs.compare(
    password,
    isUserExist.password
  );

  // If password is incorrect then return a response to user "Invalid Credentials"

  if (!isValidPassword) {
    return res.json({ success: false, message: "Invalid credentials" });
  }

  const userData = {
    id: isUserExist.id,
    username: isUserExist.username,
    email: isUserExist.email,
  };

  const token = jwt.sign(userData, process.env.JWT_CODE!, {
    expiresIn: "1d",
  });

  // all correct then return a response message "SingIn successfull"
  res.cookie("user_token", token, {
    httpOnly: true,
    sameSite: "lax", // or 'strict' depending on your use-case
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });

  return res.json({
    success: true,
    user: {
      id: isUserExist.id,
      email: isUserExist.email,
      username: isUserExist.username,
    },
    message: "SingIn successfull",
  });
});

// get Profile data
app.get("/get-user", async (req: Request, res: Response): Promise<any> => {
  const token = req.cookies.user_token;

  if (!token) {
    return res.json({ success: false, message: "Please provide token" });
  }
  const userData = jwt.verify(token, process.env.JWT_CODE!);

  return res.json({ success: true, userData });
});
app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`);
});
