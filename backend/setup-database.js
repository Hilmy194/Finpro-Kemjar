const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'vulnerable_forum.db');

async function setupDatabase() {
  const db = new sqlite3.Database(dbPath);

  try {
    console.log('Setting up SQLite database...');

    // Create users table
    await new Promise((resolve, reject) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          email TEXT,
          role TEXT DEFAULT 'user',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) reject(err);
        else {
          console.log('Users table created');
          resolve();
        }
      });
    });

    // Create posts table
    await new Promise((resolve, reject) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          author_id INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (author_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) reject(err);
        else {
          console.log('Posts table created');
          resolve();
        }
      });
    });

    // Insert sample users
    const users = [
      ['hilmy', 'hilmy123', 'hilmy@forum.com', 'admin'],
      ['andi', 'andi123', 'andi@example.com', 'user'],
      ['dika', 'dika123', 'dika@example.com', 'user'],
      ['aliya', 'aliya123', 'aliya@example.com', 'user'],
      ['putri', 'putri123', 'putri@example.com', 'user'],
      ['reza', 'reza123', 'reza@example.com', 'user']
    ];

    for (const user of users) {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
          user,
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    console.log('Sample users inserted');

    // Insert sample posts
    const posts = [
      ['Selamat Datang di Forum!', 'Ini adalah postingan pertama kami. Silakan eksplorasi dan buat postingan Anda sendiri!', 1],
      ['Tips untuk Pemula', 'Berikut beberapa tips: 1. Hormati sesama 2. Cari sebelum posting 3. Selamat belajar!', 1],
      ['Perkenalan Saya', 'Halo semua! Saya Andi dan senang bisa bergabung di komunitas ini.', 2],
      ['Pertanyaan tentang Keamanan', 'Apa saja best practice untuk keamanan aplikasi web?', 3],
      ['Cari Rekomendasi', 'Ada yang bisa rekomendasikan sumber belajar penetration testing?', 4],
      ['Belajar SQL Injection', 'Sedang belajar tentang SQL injection untuk tugas kuliah. Ada tips?', 5],
      ['Diskusi IDOR', 'Bagaimana cara mendeteksi IDOR vulnerability dalam aplikasi?', 6]
    ];

    for (const post of posts) {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT OR IGNORE INTO posts (title, content, author_id) VALUES (?, ?, ?)',
          post,
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    console.log('Sample posts inserted');

    console.log('');
    console.log('Database setup completed successfully');
    console.log('Database location:', dbPath);
    console.log('You can now run: npm start');

  } catch (error) {
    console.error('Error setting up database:', error);
    process.exit(1);
  } finally {
    db.close();
  }
}

setupDatabase();
