import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from "url"; // Required for __dirname equivalent in ES Modules

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const salt = 10;
const app = express();
const port = process.env.PORT || 3000; // Use process.env.PORT for Railway, fallback to 3000

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: ["https://backend-pedulisehat-production.up.railway.app"], // Updated origin
    methods: ["POST", "GET"],
    credentials: true,
  })
);
app.use(cookieParser());

// Serve static files from the current directory (for files like selected_gejala_v2.json)
app.use(express.static(__dirname));

// --- Database Connection (MySQL for user authentication and detection history) ---
const db = mysql.createConnection({
  host: "localhost", // Assuming database is local or configured via environment variables on Railway
  user: "root",
  password: "",
  database: "user_auth", // Ensure this database exists and has the 'login' and 'detection_history' tables
});

// Test MySQL connection
db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL database:", err);
    return;
  }
  console.log("Connected to MySQL database.");
});

// --- User Authentication and Authorization Middleware ---

// Middleware to verify JWT token and attach user name to request
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "Anda belum terautentikasi" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ Error: "Token tidak valid" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

// Middleware to get user ID from token and database
const getUserId = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "Anda belum terautentikasi" });
  }

  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ Error: "Token tidak valid" });
    }

    // Get user ID from the database using the decoded name
    const sql = "SELECT id FROM login WHERE name = ?";
    db.query(sql, [decoded.name], (err, result) => {
      if (err) {
        console.error("Error fetching user ID:", err);
        return res.json({ Error: "Error database saat mengambil ID pengguna" });
      }
      if (result.length === 0) {
        return res.json({ Error: "Pengguna tidak ditemukan" });
      }

      req.userId = result[0].id; // Attach userId to the request
      next();
    });
  });
};

// --- Authentication Routes ---

// Check if user is logged in
app.get("/is-logged-in", (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Status: "Error", Error: "Belum terautentikasi" });
  }

  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ Status: "Error", Error: "Token tidak valid" });
    }

    // Get user information from the database
    const sql = "SELECT name FROM login WHERE name = ?";
    db.query(sql, [decoded.name], (err, result) => {
      if (err || result.length === 0) {
        console.error("Error fetching user for /is-logged-in:", err);
        return res.json({ Status: "Error", Error: "Pengguna tidak ditemukan atau error database" });
      }
      return res.json({ Status: "Success", name: result[0].name });
    });
  });
});

// User registration
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.json({ Error: "Nama, email, dan password harus diisi" });
  }

  const checkSql = "SELECT email FROM login WHERE email = ?";
  db.query(checkSql, [email], (err, result) => {
    if (err) {
      console.error("Error checking existing email:", err);
      return res.json({ Error: "Error server saat memeriksa email" });
    }
    if (result.length > 0) {
      return res.json({ Error: "Email sudah terdaftar" });
    }

    bcrypt.hash(password.toString(), salt, (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.json({ Error: "Error saat mengenkripsi password" });
      }
      const sql = "INSERT INTO login (`name`,`email`,`password`) VALUES (?)";
      const values = [name, email, hash];
      db.query(sql, [values], (err, result) => {
        if (err) {
          console.error("Error inserting user data:", err);
          return res.json({ Error: "Error data di Server" });
        }
        return res.json({ Status: "Success" });
      });
    });
  });
});

// User login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ Error: "Email dan password harus diisi" });
  }

  const sql = "SELECT * FROM login WHERE email = ?";
  db.query(sql, [email], (err, data) => {
    if (err) {
      console.error("Error during login database query:", err);
      return res.json({ Error: "Error login di Server" });
    }
    if (data.length > 0) {
      bcrypt.compare(
        password.toString(),
        data[0].password,
        (err, response) => {
          if (err) {
            console.error("Error comparing password:", err);
            return res.json({ Error: "Error membandingkan password" });
          }
          if (response) {
            const name = data[0].name;
            const token = jwt.sign({ name }, "jwt-secret-key", {
              expiresIn: "1d",
            });
            res.cookie("token", token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production", // Use secure cookies in production
              sameSite: "strict", // Strict samesite policy
              maxAge: 24 * 60 * 60 * 1000, // 1 day
            });
            return res.json({ Status: "Success", name: name });
          } else {
            return res.json({ Error: "Password tidak cocok" });
          }
        }
      );
    } else {
      return res.json({ Error: "Email tidak ditemukan" });
    }
  });
});

// User logout
app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  return res.json({ Status: "Success" });
});

// --- Detection History Routes ---

// Save detection history
app.post("/save-detection", getUserId, (req, res) => {
  const { symptoms, detection_result } = req.body;
  if (!symptoms || !detection_result) {
    return res.json({ Error: "Gejala dan hasil deteksi harus diisi" });
  }

  const sql =
    "INSERT INTO detection_history (user_id, symptoms, detection_result) VALUES (?, ?, ?)";

  db.query(
    sql,
    [req.userId, JSON.stringify(symptoms), detection_result],
    (err, result) => {
      if (err) {
        console.error("Error saving detection history:", err);
        return res.json({ Error: "Error menyimpan riwayat deteksi" });
      }
      return res.json({ Status: "Success", id: result.insertId });
    }
  );
});

// Get detection history for a user
app.get("/detection-history", getUserId, (req, res) => {
  const sql =
    "SELECT * FROM detection_history WHERE user_id = ? ORDER BY created_at DESC";

  db.query(sql, [req.userId], (err, result) => {
    if (err) {
      console.error("Error fetching detection history:", err);
      return res.json({ Error: "Error mengambil riwayat deteksi" });
    }

    // Parse JSON string symptoms back to object
    const history = result.map((record) => ({
      ...record,
      symptoms: JSON.parse(record.symptoms),
    }));

    return res.json({ Status: "Success", history });
  });
});

// --- Python Prediction Routes ---

// Get absolute path to Python in the virtual environment
// Assuming venv is at the same level as server.js
const pythonPath = path.join(__dirname, "venv", "Scripts", "python.exe");

// Get list of symptoms from JSON file
app.get("/symptoms", async (req, res) => {
  try {
    console.log("Membaca gejala dari selected_gejala_v2.json");
    const data = await fs.readFile(path.join(__dirname, "selected_gejala_v2.json"), "utf8");
    const symptoms = JSON.parse(data);
    console.log(`Ditemukan ${symptoms.length} gejala`);
    res.json({
      success: true,
      symptoms: symptoms,
    });
  } catch (error) {
    console.error("Error membaca gejala:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Perform prediction using Python script
app.post("/predict", async (req, res) => {
  const symptoms = req.body.symptoms;
  if (!symptoms || !Array.isArray(symptoms)) {
    return res.status(400).json({
      success: false,
      error: "Data gejala tidak valid",
    });
  }

  try {
    const tempInputPath = path.join(__dirname, "temp_input.json");
    await fs.writeFile(tempInputPath, JSON.stringify(symptoms));

    // Spawn Python child process
    const python = spawn(pythonPath, ["predict.py"]);
    let dataString = "";
    let errorString = "";

    python.stdout.on("data", (data) => {
      dataString += data.toString();
    });

    python.stderr.on("data", (data) => {
      console.error(`Error Python: ${data}`);
      errorString += data.toString();
    });

    python.on("close", async (code) => {
      try {
        // Only try to delete if the file exists
        await fs.access(tempInputPath)
          .then(() => fs.unlink(tempInputPath))
          .catch(() => {}); // Ignore if file doesn't exist or other unlink error

        if (code !== 0) {
          console.error("Proses Python keluar dengan kode:", code);
          console.error("Output error:", errorString);
          return res.status(500).json({
            success: false,
            error: "Error menjalankan script prediksi",
          });
        }

        const result = JSON.parse(dataString);
        res.json(result);
      } catch (error) {
        console.error("Error processing Python result:", error);
        res.status(500).json({
          success: false,
          error: "Error memproses hasil prediksi",
        });
      }
    });
  } catch (error) {
    console.error("Server error during prediction:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`); // For local testing
  console.log(`Aplikasi mungkin juga berjalan di: https://backend-pedulisehat-production.up.railway.app`); // For Railway deployment
  console.log("Menggunakan Python dari:", pythonPath);
  console.log("Pastikan Anda memiliki semua file yang diperlukan:");
  console.log("- predict.py");
  console.log("- train1_model_v2.joblib");
  console.log("- label_train_v2.joblib");
  console.log("- selected_gejala_v2.json");
  console.log("Dan pastikan Anda memiliki database MySQL 'user_auth' dengan tabel 'login' dan 'detection_history'.");
});
