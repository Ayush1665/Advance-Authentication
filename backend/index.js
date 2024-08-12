// const express=require('express');     OR
import express from "express";
import dotenv from "dotenv";

import { connectDB } from "./db/connectDB.js";
import authRoutes from "./routes/auth.route.js"; 

const app=express();
const PORT=process.env.PORT ||5000;

dotenv.config();

app.use(express.json());   // allows us to parse incoming requests:req.body 
app.use("/api/auth",authRoutes);

app.listen(PORT, ()=>{
  connectDB();
  console.log("Server started at port:",PORT);
});

