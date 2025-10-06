const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
// Configure CORS: if ALLOWED_ORIGINS is set, restrict to those origins (comma-separated). Otherwise allow all for demo.
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '';
if(ALLOWED_ORIGINS){
  const origins = ALLOWED_ORIGINS.split(',').map(s=>s.trim()).filter(Boolean);
  app.use(cors({ origin: function(origin, cb){
    // allow non-browser requests (e.g., curl) with no origin
    if(!origin) return cb(null, true);
    if(origins.indexOf(origin) !== -1) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  }}));
} else {
  app.use(cors());
}
app.use(bodyParser.json());

const STORAGE = path.join(__dirname, 'users.json');
let db = { users: {}, pending: {} };
const NODE_ENV = process.env.NODE_ENV || 'production';
// For convenience in local testing, allow setting MASTER_OTP; it will only be active when running in development and the request originates from localhost.
const RAW_MASTER_OTP = process.env.MASTER_OTP || '123456';
const MASTER_OTP = NODE_ENV === 'development' ? RAW_MASTER_OTP : null;
// When true, server will include the generated OTP in the /signup response (dev only)
const EXPOSE_OTP = (process.env.EXPOSE_OTP === 'true' || NODE_ENV === 'development');
// HR admin token required to approve/reject/list pending. Set HR_TOKEN in env for production.
const HR_TOKEN = process.env.HR_TOKEN || null;
// When true (default), generate a temporary password on employee approve and return it in the response (demo convenience).
const APPROVE_GENERATE_TEMP_PASSWORD = process.env.APPROVE_GENERATE_TEMP_PASSWORD !== 'false';

function genTempPassword(len = 8){
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  for(let i=0;i<len;i++) out += chars[Math.floor(Math.random()*chars.length)];
  return out;
}

function isLocalhostReq(req){
  const ip = (req.ip || req.connection && req.connection.remoteAddress || '').replace(/^::ffff:/,'');
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

function requireHrAuth(req,res,next){
  if(HR_TOKEN){
    const header = req.get('x-hr-token');
    if(header && header === HR_TOKEN) return next();
    return res.status(403).json({ error: 'HR token required' });
  }
  // If no HR_TOKEN configured, allow in development (but log) and deny in production
  if(NODE_ENV === 'development'){
    console.warn('[demo-server] HR_TOKEN not set; allowing admin actions in development');
    return next();
  }
  return res.status(403).json({ error: 'HR token required' });
}

// Simple audit logger (appends JSON lines to audit.log). Avoid logging secrets like passwords.
function audit(action, details, req){
  try{
    const ip = (req && (req.ip || (req.connection && req.connection.remoteAddress)) || '') .replace(/^::ffff:/,'');
    let actor = 'unknown';
    if(req){
      const header = req.get && req.get('x-hr-token');
      if(header) actor = 'hr_token:' + (String(header).slice(0,4) + '...');
      else if(isLocalhostReq(req)) actor = 'localhost';
      else actor = 'remote';
    }
    const entry = { ts: new Date().toISOString(), action, ip, actor, details };
    fs.appendFileSync(path.join(__dirname,'audit.log'), JSON.stringify(entry) + '\n');
  }catch(e){ console.warn('[demo-server] audit failed', e && e.message); }
}

function load(){
  try{ db = JSON.parse(fs.readFileSync(STORAGE)); }catch(e){ db = { users: {}, pending: {} }; }
}
function save(){ fs.writeFileSync(STORAGE, JSON.stringify(db, null, 2)); }
load();

app.get('/health', (req,res)=> res.json({ok:true}));

// Signup: creates a pending OTP and returns masked contact and requestId
app.post('/signup', (req,res)=>{
  // supports role-based ids: role and id (id is employeeId or customerId etc)
  const { role = 'employee', id, name, dept, email, contact, password } = req.body || {};
  if(!name || !id || !password) return res.status(400).json({error:'name, id and password required'});
  const key = `${role}:${id}`;
  if(db.users[key]) return res.status(409).json({error:'user exists'});

  const requestId = uuidv4();
  const otp = String(Math.floor(100000 + Math.random()*900000));
  const expiresAt = Date.now() + 5*60*1000;
  db.pending[requestId] = { role, id, name, dept, email, contact, passwordHash: bcrypt.hashSync(password, 10), otp, expiresAt };
  save();
  console.log('[demo-server] OTP for', contact, '->', otp);
  const resp = { requestId, masked: mask(contact) };
  if(EXPOSE_OTP){
    // include OTP in response for demo/testing only
    resp.otp = otp;
  }
  res.json(resp);
});

// Verify OTP and persist user
app.post('/verify-otp', (req,res)=>{
  const { requestId, otp } = req.body || {};
  const record = db.pending[requestId];
  if(!record) return res.status(404).json({error:'request not found'});
  if(Date.now() > record.expiresAt) { delete db.pending[requestId]; save(); return res.status(410).json({error:'otp expired'}); }
  // accept master OTP (useful for testing) only when running in development AND the request comes from localhost
  const usedMaster = MASTER_OTP && NODE_ENV === 'development' && isLocalhostReq(req) && String(otp) === String(MASTER_OTP);
  if(!usedMaster && record.otp !== String(otp)) return res.status(400).json({error:'invalid otp'});
  if(usedMaster) console.log('[demo-server] master OTP used for request', requestId);
  // If master OTP used, auto-approve immediately (for dev/test convenience)
  if(usedMaster){
    if(record.role === 'employee'){
      // assign employee id immediately and persist user
      const existing = Object.keys(db.users).filter(k=>k.startsWith('employee:')).length;
      const next = existing + 1;
      const assignedId = 'EMP' + String(next).padStart(4,'0');
      const key = `${record.role}:${assignedId}`;
      let tempPassword = null;
      let passwordHash = record.passwordHash;
      if(APPROVE_GENERATE_TEMP_PASSWORD){
        tempPassword = genTempPassword(8);
        passwordHash = bcrypt.hashSync(tempPassword, 10);
      }
      db.users[key] = { role: record.role, id: assignedId, name: record.name, dept: record.dept, email: record.email, contact: record.contact, passwordHash };
      delete db.pending[requestId];
      save();
      console.log('[demo-server] master OTP auto-approved employee, assigned id', assignedId);
  audit('auto_approve_master_otp', { requestId, assignedId, role: record.role, name: record.name, email: record.email }, req);
      const resp = { ok:true, role: record.role, id: assignedId, name: record.name, note: 'auto_approved_master_otp' };
      if(tempPassword) resp.tempPassword = tempPassword;
      return res.json(resp);
    }
    // for non-employee roles, create user immediately using provided id
    const key = `${record.role}:${record.id}`;
  db.users[key] = { role: record.role, id: record.id, name: record.name, dept: record.dept, email: record.email, contact: record.contact, passwordHash: record.passwordHash };
    delete db.pending[requestId];
    save();
  console.log('[demo-server] master OTP auto-approved user', key);
  audit('auto_approve_master_otp', { requestId, key, role: record.role, name: record.name, email: record.email }, req);
  return res.json({ok:true, role: record.role, id: record.id, name: record.name, note: 'auto_approved_master_otp'});
  }

  // For employee role, mark as verified and wait for HR approval
  if(record.role === 'employee'){
    record.verified = true;
    save();
    return res.json({ok:true, role: record.role, requestId, status: 'pending_approval', name: record.name});
  }

  // For other roles, create the user immediately
  const key = `${record.role}:${record.id}`;
  db.users[key] = { role: record.role, id: record.id, name: record.name, dept: record.dept, email: record.email, contact: record.contact, passwordHash: record.passwordHash };
  delete db.pending[requestId];
  save();
  res.json({ok:true, role: record.role, id: record.id, name: record.name});
});

// List pending signups (optionally filter by role)
app.get('/pending', requireHrAuth, (req,res)=>{
  const { role } = req.query || {};
  const list = Object.entries(db.pending).map(([requestId, rec])=> ({ requestId, ...rec }));
  const filtered = role ? list.filter(r => r.role === role) : list;
  res.json(filtered);
});

// Approve a pending signup: generate role-specific id for employees, persist user
app.post('/approve', requireHrAuth, (req,res)=>{
  const { requestId } = req.body || {};
  const record = db.pending[requestId];
  if(!record) return res.status(404).json({error:'request not found'});
  if(!record.verified) return res.status(400).json({error:'not verified yet'});

  let assignedId = record.id;
  if(record.role === 'employee'){
    // generate employee id: EMP0001 style
    const existing = Object.keys(db.users).filter(k=>k.startsWith('employee:')).length;
    const next = existing + 1;
    assignedId = 'EMP' + String(next).padStart(4,'0');
  }

  const key = `${record.role}:${assignedId}`;
  if(db.users[key]) return res.status(409).json({error:'assigned id already exists'});

  let tempPassword = null;
  let passwordHash = record.passwordHash;
  if(record.role === 'employee' && APPROVE_GENERATE_TEMP_PASSWORD){
    tempPassword = genTempPassword(8);
    passwordHash = bcrypt.hashSync(tempPassword, 10);
  }

  db.users[key] = { role: record.role, id: assignedId, name: record.name, dept: record.dept, email: record.email, contact: record.contact, passwordHash };
  delete db.pending[requestId];
  save();
  const resp = { ok:true, role: record.role, id: assignedId, name: record.name };
  if(tempPassword) resp.tempPassword = tempPassword;
  // audit the approval (do not include password)
  audit('approve', { requestId, assignedId, role: record.role, name: record.name, email: record.email }, req);
  res.json(resp);
});

// Reject pending signup
app.post('/reject', requireHrAuth, (req,res)=>{
  const { requestId } = req.body || {};
  const record = db.pending[requestId];
  if(!record) return res.status(404).json({error:'request not found'});
  delete db.pending[requestId];
  save();
  audit('reject', { requestId, role: record.role, name: record.name, email: record.email }, req);
  res.json({ok:true});
});

// Login
app.post('/login', (req,res)=>{
  // accepts { role, id, password }
  const { role = 'employee', id, password } = req.body || {};
  if(!id || !password) return res.status(400).json({error:'id and password required'});
  const key = `${role}:${id}`;
  const user = db.users[key];
  if(!user) return res.status(404).json({error:'not found'});
  if(!bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({error:'invalid credentials'});
  // demo: return a simple token
  const token = uuidv4();
  res.json({ok:true, token, role, id, name: user.name, dept: user.dept, email: user.email, contact: user.contact});
});

function mask(c){ if(!c) return 'unknown'; if(c.includes('@')){ const p=c.split('@'); return p[0][0]+'***@'+p[1]; } return c.length<=4 ? '***'+c : c.slice(0,2)+'***'+c.slice(-2); }

const port = process.env.PORT || 3001;
app.listen(port, ()=> {
  console.log('Demo auth server listening on', port);
  if(MASTER_OTP) console.log('[demo-server] MASTER_OTP is enabled (dev only)');
});
