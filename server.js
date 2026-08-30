import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import Database from "better-sqlite3";
import dotenv from "dotenv";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express(), PORT=process.env.PORT||3000;
const db=new Database(path.join(__dirname,"data","panel.db"));
const SECRET=process.env.JWT_SECRET||"CHANGE_ME_BEFORE_LAUNCH";

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,balance REAL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY,icon TEXT,name TEXT NOT NULL,description TEXT,price_per_1000 REAL NOT NULL,min_qty INTEGER NOT NULL,max_qty INTEGER NOT NULL,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS offers(id INTEGER PRIMARY KEY,title TEXT NOT NULL,tag TEXT,description TEXT,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id INTEGER,service_id INTEGER,link TEXT,quantity INTEGER,price REAL,status TEXT DEFAULT 'Pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,user_id INTEGER,method TEXT,amount REAL,transaction_id TEXT,screenshot_path TEXT,status TEXT DEFAULT 'Pending',admin_note TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);

if(!db.prepare("SELECT COUNT(*) c FROM services").get().c){
 const q=db.prepare("INSERT INTO services(icon,name,description,price_per_1000,min_qty,max_qty) VALUES(?,?,?,?,?,?)");
 [["🎵","TikTok Views","Public TikTok content service.",40,100,100000],["📸","Instagram Followers","Public Instagram profile service.",120,100,50000],["▶️","YouTube Views","Public YouTube video service.",60,100,100000],["🔵","Facebook Engagement","Public Facebook content service.",80,100,50000],["𝕏","X Services","Available X services.",90,100,50000],["✨","Other Services","Additional available services.",100,100,50000]].forEach(x=>q.run(...x));
 db.prepare("INSERT INTO offers(title,tag,description) VALUES(?,?,?)").run("Welcome Offer","NEW USER","Create your account and explore available services.");
}

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(cookieParser());
app.use("/api/",rateLimit({windowMs:15*60*1000,max:200}));
app.use(express.static(path.join(__dirname,"public")));

const upload=multer({storage:multer.diskStorage({destination:(_,__,cb)=>cb(null,path.join(__dirname,"uploads")),filename:(_,f,cb)=>cb(null,crypto.randomUUID()+path.extname(f.originalname).toLowerCase())}),limits:{fileSize:5*1024*1024},fileFilter:(_,f,cb)=>["image/jpeg","image/png","image/webp"].includes(f.mimetype)?cb(null,true):cb(new Error("Only JPG, PNG or WEBP images allowed"))});

function setAuth(res,u){res.cookie("cb_token",jwt.sign({id:u.id,email:u.email,role:u.role||"user"},SECRET,{expiresIn:"7d"}),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});}
function auth(req,res,next){try{req.user=jwt.verify(req.cookies.cb_token||"",SECRET);next()}catch{res.status(401).json({error:"Please log in first"});}}
function admin(req,res,next){if(req.user?.role==="admin")next();else res.status(403).json({error:"Admin access required"});}

app.post("/api/auth/register",async(req,res)=>{
 const {name,email,password}=req.body, e=(email||"").trim().toLowerCase();
 if(!name?.trim()||!e||!password||password.length<8||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))return res.status(400).json({error:"Enter a name, valid email format and password of at least 8 characters."});
 if(db.prepare("SELECT id FROM users WHERE email=?").get(e))return res.status(409).json({error:"This email is already registered."});
 const hash=await bcrypt.hash(password,12);
 const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),e,hash);
 const user={id:info.lastInsertRowid,email:e}; setAuth(res,user);
 res.json({ok:true,message:"Account created successfully.",user:{name:name.trim(),email:e,balance:0}});
});
app.post("/api/auth/login",async(req,res)=>{
 const {email,password}=req.body,e=(email||"").trim().toLowerCase();
 if(e===(process.env.ADMIN_EMAIL||"").toLowerCase()&&process.env.ADMIN_PASSWORD&&password===process.env.ADMIN_PASSWORD){setAuth(res,{id:0,email:e,role:"admin"});return res.json({ok:true,admin:true});}
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(e);
 if(!u||!(await bcrypt.compare(password||"",u.password_hash)))return res.status(401).json({error:"Invalid email or password."});
 setAuth(res,u);res.json({ok:true,user:{id:u.id,name:u.name,email:u.email,balance:u.balance}});
});
app.post("/api/auth/logout",(_,res)=>{res.clearCookie("cb_token");res.json({ok:true});});

app.get("/api/public",(_,res)=>res.json({services:db.prepare("SELECT * FROM services WHERE active=1 ORDER BY id DESC").all(),offers:db.prepare("SELECT * FROM offers WHERE active=1 ORDER BY id DESC").all(),paymentInstructions:{easypaisaName:"Shahzaib Hussain",easypaisaNumber:"03476277164",whatsapp:"03406742924"}}));
app.get("/api/me",auth,(req,res)=>{if(req.user.role==="admin")return res.json({admin:true,email:req.user.email});const u=db.prepare("SELECT id,name,email,balance,created_at FROM users WHERE id=?").get(req.user.id);const orders=db.prepare("SELECT o.*,s.name service_name FROM orders o JOIN services s ON s.id=o.service_id WHERE o.user_id=? ORDER BY o.created_at DESC").all(req.user.id);res.json({user:u,orders});});
app.post("/api/orders",auth,(req,res)=>{
 if(req.user.role==="admin")return res.status(400).json({error:"Admin cannot place customer orders."});
 const s=db.prepare("SELECT * FROM services WHERE id=? AND active=1").get(req.body.service_id),q=Number(req.body.quantity);
 if(!s||!Number.isInteger(q)||q<s.min_qty||q>s.max_qty)return res.status(400).json({error:"Invalid service or quantity."});
 try{new URL(req.body.link)}catch{return res.status(400).json({error:"Enter a valid public URL."})}
 const price=Number((q/1000*s.price_per_1000).toFixed(2)),u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id);
 if(u.balance<price)return res.status(400).json({error:`Insufficient balance. Required: Rs ${price.toFixed(2)}. Add balance first.`});
 const id="ORD-"+Date.now()+"-"+Math.floor(Math.random()*10000);
 db.transaction(()=>{db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(price,req.user.id);db.prepare("INSERT INTO orders(id,user_id,service_id,link,quantity,price) VALUES(?,?,?,?,?,?)").run(id,req.user.id,s.id,req.body.link.trim(),q,price);})();res.json({ok:true,id,price});
});
app.post("/api/payments",auth,upload.single("screenshot"),(req,res)=>{
 if(req.user.role==="admin")return res.status(400).json({error:"Invalid request"});
 const {method,amount,transaction_id}=req.body;
 if(!method||!transaction_id?.trim()||!req.file||Number(amount)<=0)return res.status(400).json({error:"Method, amount, transaction ID and payment screenshot are required."});
 const id="PAY-"+Date.now()+"-"+Math.floor(Math.random()*10000);
 db.prepare("INSERT INTO payments(id,user_id,method,amount,transaction_id,screenshot_path) VALUES(?,?,?,?,?,?)").run(id,req.user.id,method,Number(amount),transaction_id.trim(),req.file.filename);
 res.json({ok:true,message:"Payment request submitted and is now Pending admin confirmation."});
});

app.get("/api/admin/summary",auth,admin,(_,res)=>res.json({users:db.prepare("SELECT COUNT(*) c FROM users").get().c,services:db.prepare("SELECT COUNT(*) c FROM services").get().c,orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,pendingPayments:db.prepare("SELECT COUNT(*) c FROM payments WHERE status='Pending'").get().c}));
for(const type of ["services","offers"]){
 app.get(`/api/admin/${type}`,auth,admin,(_,res)=>res.json(db.prepare(`SELECT * FROM ${type} ORDER BY id DESC`).all()));
}
app.post("/api/admin/services",auth,admin,(req,res)=>{const x=req.body;db.prepare("INSERT INTO services(icon,name,description,price_per_1000,min_qty,max_qty,active) VALUES(?,?,?,?,?,?,?)").run(x.icon,x.name,x.description,Number(x.price_per_1000),Number(x.min_qty),Number(x.max_qty),x.active?1:0);res.json({ok:true});});
app.put("/api/admin/services/:id",auth,admin,(req,res)=>{const x=req.body;db.prepare("UPDATE services SET icon=?,name=?,description=?,price_per_1000=?,min_qty=?,max_qty=?,active=? WHERE id=?").run(x.icon,x.name,x.description,Number(x.price_per_1000),Number(x.min_qty),Number(x.max_qty),x.active?1:0,req.params.id);res.json({ok:true});});
app.delete("/api/admin/services/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM services WHERE id=?").run(req.params.id);res.json({ok:true});});
app.post("/api/admin/offers",auth,admin,(req,res)=>{const x=req.body;db.prepare("INSERT INTO offers(title,tag,description,active) VALUES(?,?,?,?)").run(x.title,x.tag,x.description,x.active?1:0);res.json({ok:true});});
app.put("/api/admin/offers/:id",auth,admin,(req,res)=>{const x=req.body;db.prepare("UPDATE offers SET title=?,tag=?,description=?,active=? WHERE id=?").run(x.title,x.tag,x.description,x.active?1:0,req.params.id);res.json({ok:true});});
app.delete("/api/admin/offers/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM offers WHERE id=?").run(req.params.id);res.json({ok:true});});
app.get("/api/admin/orders",auth,admin,(_,res)=>res.json(db.prepare("SELECT o.*,u.name user_name,u.email user_email,s.name service_name FROM orders o JOIN users u ON u.id=o.user_id JOIN services s ON s.id=o.service_id ORDER BY o.created_at DESC").all()));
app.put("/api/admin/orders/:id",auth,admin,(req,res)=>{if(!["Pending","Processing","Completed","Cancelled"].includes(req.body.status))return res.status(400).json({error:"Invalid status"});db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true});});
app.get("/api/admin/users",auth,admin,(_,res)=>res.json(db.prepare("SELECT id,name,email,balance,created_at FROM users ORDER BY id DESC").all()));
app.get("/api/admin/payments",auth,admin,(_,res)=>res.json(db.prepare("SELECT p.*,u.name user_name,u.email user_email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC").all()));
app.get("/api/admin/payment-screenshot/:id",auth,admin,(req,res)=>{const p=db.prepare("SELECT screenshot_path FROM payments WHERE id=?").get(req.params.id);if(!p)return res.status(404).end();res.sendFile(path.join(__dirname,"uploads",p.screenshot_path));});
app.put("/api/admin/payments/:id",auth,admin,(req,res)=>{const p=db.prepare("SELECT * FROM payments WHERE id=?").get(req.params.id);if(!p||p.status!=="Pending")return res.status(400).json({error:"Payment is not pending"});if(!["Approved","Rejected"].includes(req.body.status))return res.status(400).json({error:"Invalid status"});db.transaction(()=>{db.prepare("UPDATE payments SET status=?,admin_note=? WHERE id=?").run(req.body.status,req.body.admin_note||"",p.id);if(req.body.status==="Approved")db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(p.amount,p.user_id);})();res.json({ok:true});});
app.use((e,_,res,next)=>res.status(500).json({error:e.message||"Server error"}));
app.listen(PORT,()=>console.log(`Chattha Boost running on port ${PORT}`));