import express, { response } from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt, { hash } from "bcrypt";
import cookieParser from "cookie-parser";
const salt = 10;

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173"],
    methods: ["POST", "GET"],
    credentials: true,
  })
);
app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "user_auth",
});

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
    
    // Dapatkan informasi pengguna dari database
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

    // Dapatkan ID pengguna dari database menggunakan nama yang didekode
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

    // Parse string JSON gejala kembali ke objek
    const history = result.map((record) => ({
      ...record,
      symptoms: JSON.parse(record.symptoms),
    }));

    return res.json({ Status: "Success", history });
  });
});

app.listen(8081, () => {
  console.log("Sudah Running yaa...");
});
