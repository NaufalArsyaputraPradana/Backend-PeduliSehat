import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const salt = 10;
const authPort = 8081;
const mlPort = 3000;

const app = express();

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173"],
    methods: ["POST", "GET"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.static("."));

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "user_auth",
});

// Dapatkan path absolut ke Python di lingkungan virtual
const pythonPath = path.join(__dirname, "venv", "Scripts", "python.exe");

// ==================== AUTHENTICATION ROUTES ====================

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

app.get("/is-logged-in", (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Status: "Error", Error: "Belum terautentikasi" });
  }
  
  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ Status: "Error", Error: "Token tidak valid" });
    }
    
    const sql = "SELECT name FROM login WHERE name = ?";
    db.query(sql, [decoded.name], (err, result) => {
      if (err || result.length === 0) {
        return res.json({ Status: "Error", Error: "Pengguna tidak ditemukan" });
      }
      return res.json({ Status: "Success", name: result[0].name });
    });
  });
});

app.post("/register", (req, res) => {
  const sql = "INSERT INTO login (`name`,`email`,`password`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: "Error saat mengenkripsi password" });
    const values = [req.body.name, req.body.email, hash];
    db.query(sql, [values], (err, result) => {
      if (err) return res.json({ Error: "Error data di Server" });
      return res.json({ Status: "Success" });
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM login WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Error login di Server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) return res.json({ Error: "Error membandingkan password" });
          if (response) {
            const name = data[0].name;
            const token = jwt.sign({ name }, "jwt-secret-key", {
              expiresIn: "1d",
            });
            res.cookie("token", token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production",
              sameSite: "strict",
              maxAge: 24 * 60 * 60 * 1000 // 1 hari
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

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: "Success" });
});

// Dapatkan ID pengguna dari token
const getUserId = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "Anda belum terautentikasi" });
  }

  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      return res.json({ Error: "Token tidak valid" });
    }

    const sql = "SELECT id FROM login WHERE name = ?";
    db.query(sql, [decoded.name], (err, result) => {
      if (err) return res.json({ Error: "Error database" });
      if (result.length === 0) return res.json({ Error: "Pengguna tidak ditemukan" });

      req.userId = result[0].id;
      next();
    });
  });
};

// Simpan riwayat deteksi
app.post("/save-detection", getUserId, (req, res) => {
  const { symptoms, detection_result } = req.body;
  const sql =
    "INSERT INTO detection_history (user_id, symptoms, detection_result) VALUES (?, ?, ?)";

  db.query(
    sql,
    [req.userId, JSON.stringify(symptoms), detection_result],
    (err, result) => {
      if (err) return res.json({ Error: "Error menyimpan riwayat deteksi" });
      return res.json({ Status: "Success", id: result.insertId });
    }
  );
});

// Dapatkan riwayat deteksi pengguna
app.get("/detection-history", getUserId, (req, res) => {
  const sql =
    "SELECT * FROM detection_history WHERE user_id = ? ORDER BY created_at DESC";

  db.query(sql, [req.userId], (err, result) => {
    if (err) return res.json({ Error: "Error mengambil riwayat deteksi" });

    const history = result.map((record) => ({
      ...record,
      symptoms: JSON.parse(record.symptoms),
    }));

    return res.json({ Status: "Success", history });
  });
});

// ==================== MACHINE LEARNING ROUTES ====================

// Dapatkan daftar gejala
app.get("/symptoms", async (req, res) => {
  try {
    console.log("Membaca gejala dari selected_gejala_v2.json");
    const data = await fs.readFile("selected_gejala_v2.json", "utf8");
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

// Lakukan prediksi
app.post("/predict", async (req, res) => {
  const symptoms = req.body.symptoms;
  if (!symptoms || !Array.isArray(symptoms)) {
    return res.status(400).json({
      success: false,
      error: "Data gejala tidak valid",
    });
  }

  try {
    await fs.writeFile("temp_input.json", JSON.stringify(symptoms));

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

    python.on("close", (code) => {
      try {
        // Hanya coba hapus jika file ada
        fs.access("temp_input.json")
          .then(() => fs.unlink("temp_input.json"))
          .catch(() => {}); // Abaikan jika file tidak ada

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
        console.error("Error memproses hasil:", error);
        res.status(500).json({
          success: false,
          error: "Error memproses hasil prediksi",
        });
      }
    });
  } catch (error) {
    console.error("Error server:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Start server
app.listen(authPort, () => {
  console.log(`Authentication server berjalan di http://localhost:${authPort}`);
});

app.listen(mlPort, () => {
  console.log(`ML server berjalan di http://localhost:${mlPort}`);
  console.log("Menggunakan Python dari:", pythonPath);
  console.log("Pastikan Anda memiliki semua file yang diperlukan:");
  console.log("- train1_model_v2.joblib");
  console.log("- label_train_v2.joblib");
  console.log("- selected_gejala_v2.json");
});