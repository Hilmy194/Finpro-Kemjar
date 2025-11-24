const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'vulnerable_forum.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully');
  }
});

const query = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    if (sql.trim().toUpperCase().startsWith('SELECT') || sql.trim().toUpperCase().startsWith('WITH')) {
      db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve({ rows });
      });
    } else if (sql.trim().toUpperCase().startsWith('INSERT')) {
      db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ rows: [{ id: this.lastID }] });
      });
    } else if (sql.trim().toUpperCase().startsWith('UPDATE') && sql.toUpperCase().includes('RETURNING')) {
      // Handle UPDATE with RETURNING clause (SQLite doesn't support RETURNING)
      const updateSql = sql.split(/RETURNING/i)[0].trim();
      const returningCols = sql.split(/RETURNING/i)[1].trim();
      
      db.run(updateSql, params, function(err) {
        if (err) {
          reject(err);
        } else {
          const changes = this.changes;
          if (changes > 0) {
            // Extract WHERE clause to get the updated row
            const whereMatch = updateSql.match(/WHERE\s+(.+?)(?:$|;)/i);
            if (whereMatch) {
              const whereClause = whereMatch[1];
              const selectSql = `SELECT ${returningCols} FROM users WHERE ${whereClause}`;
              // Get SELECT params (last params used in WHERE clause)
              const selectParams = params.slice(-1);
              
              db.all(selectSql, selectParams, (err, rows) => {
                if (err) reject(err);
                else resolve({ rows, rowCount: changes });
              });
            } else {
              resolve({ rows: [], rowCount: changes });
            }
          } else {
            resolve({ rows: [], rowCount: 0 });
          }
        }
      });
    } else {
      db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ rows: [], rowCount: this.changes });
      });
    }
  });
};

module.exports = { query, db };

