import bcryptjs from 'bcryptjs';
import crypto from 'crypto';
import { User } from '../models/user.model.js';
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { sendVerificationEmail } from "../mailtrap/emails.js";
import { sendWelcomeEmail } from '../mailtrap/emails.js';
import { sendPasswordResetEmail } from '../mailtrap/emails.js';
import { sendResetSuccessEmail } from '../mailtrap/emails.js';

export const signup=async(req,res)=>{
  // Postman
  const {email,password,name}=req.body;

  try{
    if(!email || !password || !name){
      throw new Error("All Fields are required");
    } 

    const userAlreadyExists=await User.findOne({email});
    if(userAlreadyExists){
      return res.status(400).json({success:false,message:"User already exists"}); 
    }

    const hashedPassword=await bcryptjs.hash(password,10);
    const verificationToken=Math.floor(100000+Math.random()*90000).toString();

    const user=new User({
      email,
      password:hashedPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt:Date.now()+ 24 * 60 * 60 * 1000  //24 hours
    })

    await user.save();

    //jwt
    generateTokenAndSetCookie(res,user._id);

    await sendVerificationEmail(user.email,verificationToken);

    res.status(201).json({         //new resource has been created
      success:true,
      message:"User created successfully",
      user:{
        ...user._doc,
        password:undefined
      },
    }); 
  }
  catch(error){
     res.status(400).json({success:false,message:error.message});
  }
}

export const verifyEmail=async(req,res)=>{
  const { code } = req.body;
  try{
    const user=await User.findOne({
      verificationToken:code,
      verificationTokenExpiresAt:{$gt:Date.now()}
    })

    if(!user){
      return res.status(400).json({success:false,message:"Invalid or expired verification code"})
    }
    user.isVerified=true;
    user.verificationToken=undefined;
    user.verificationTokenExpiresAt=undefined;
    await user.save();

    await sendWelcomeEmail(user.email,user.name);

    res.status(200).json({
      success:true,
      message:"Email verified successfully",
      user:{
        ...user._doc,
        password:undefined,
      }
    })
  }
  
  catch(error){
    console.log("error in verifyEmail",error);
    res.status(500).json({success:false,message:"Server Error"});
  }
}

export const login=async(req,res)=>{
  const {email,password}=req.body;
  try{
    const user=await User.findOne({email});
    if(!user){
      return res.status(400).json({ success:false, message:"Invalid credentials"});
    }
    const isPasswordValid=await bcryptjs.compare(password,user.password);
    if(!isPasswordValid){
      return res.status(400).json({ success:false, message:"Invalid credentials"});
    }

    generateTokenAndSetCookie(res,user._id);

    user.lastLogin=new Date();
    await user.save();

    res.status(200).json({
      success:true,
      message:"Logged in Successfully",
      user:{
        ...user._doc,
        password:undefined,
      },
    });
  }catch(error){
    console.log("Error in Login",error);
    res.status(400).json({success:false,message:error.message});
  }
};

export const logout=async(req,res)=>{
  res.clearCookie("token");
  res.status(200).json({success:true,message:"Logged out successfully"}); 
};

export const forgotPassword=async(req,res)=>{
  const { email  }= req.body;
  try{
    const user=await User.findOne({ email });
    if(!user){
      return res.status(400).json({ success:false, message:"User not found"});
    }
    // Reset Token
    const resetToken=crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt=Date.now()+ 1 * 60 *60 * 1000;
    
    user.resetPasswordToken=resetToken;
    user.resetPasswordExpiresAt=resetTokenExpiresAt;

    await user.save();

    // Send Email
    await sendPasswordResetEmail(user.email,`${process.env.CLIENT_URL}/reset-password/${resetToken}`);

    res.status(200).json({success:true, message:"Password reset link sent to your email"});
  }catch(error){
    console.log("Error in forgot Password",error);
    res.status(400).json({success:false, message:error.message});
  }
}

export const resetPassword=async(req,res)=>{
  try{
    const { token }=req.params;
    const {password}=req.body;

    const user =await User.findOne({
      resetPasswordToken:token,
      resetPasswordExpiresAt:{$gt:Date.now()},
    });
    if(!user){
      return res.status(400).json({success:false, message:"Invalid or expired reset token"});
    }

    // Update Password
    const hashedPassword=await bcryptjs.hash(password,10);

    user.password=hashedPassword;
    user.resetPasswordToken=undefined;
    user.resetPasswordExpiresAt=undefined;
    await user.save();

    await sendResetSuccessEmail(user.email);

    res.status(200).json({success:true, message:"Password reset successfully"});
  }catch(error){
    console.log("Error in resetPassword",error);
    res.status(400).json({success:false, message:error.message});
  }
}