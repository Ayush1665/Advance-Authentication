import { secureHeapUsed } from "crypto";
import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie=(res,userId)=>{
  const token=jwt.sign({ userId },process.env.JWT_SECRET,{
    expiresIn:"7d",
  })
  res.cookie("token",token,{
    httpOnly:true,   // Cookie cannot be accessed by client side
    secure:process.env.NODE_ENV==="production",
    sameSite:"strict",  // csrf
    maxAge:7 * 24 * 60 * 60 * 1000,
  });
  return token;
}