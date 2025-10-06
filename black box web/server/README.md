Demo Auth Server

This small Express server demonstrates signup with OTP and login for the front-end demo.

Requirements
- Node.js 16+ (or compatible)

Install & run (PowerShell on Windows):

```powershell
cd "d:\black box web\server"
npm install
npm start
```

Endpoints
- POST /signup { name, dept, employeeId, email, contact, password } -> { requestId, masked }
- POST /verify-otp { requestId, otp } -> { ok, employeeId, name }
- POST /login { employeeId, password } -> { ok, token, employeeId, name }

Notes
- OTPs are printed to server console for demo. Replace with real SMS/email provider in production.
- Passwords are hashed with bcrypt in this demo server.
- Storage is a simple JSON file `users.json`. For production use a database.

Front-end integration
- The `employee.html` page is configured to use `http://localhost:3001` as the demo server (variable SERVER_BASE). If you run the server locally, the front-end will call `/signup`, `/verify-otp`, and `/login`.
- If the server is not reachable, `employee.html` falls back to a client-only demo mode that stores users in localStorage and prints OTPs to the browser console.
