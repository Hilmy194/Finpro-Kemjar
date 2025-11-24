const pool = require('../config/database');

exports.getAllUsers = async (req, res) => {
  try {
    const query = `SELECT id, username, email, role, created_at FROM users ORDER BY id`;
    const result = await pool.query(query);
    
    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
};

// VULNERABLE: IDOR - No authorization check
exports.getUserById = async (req, res) => {
  const { id } = req.params;

  try {
    const query = `SELECT id, username, email, role, created_at FROM users WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length > 0) {
      res.json({
        success: true,
        user: result.rows[0]
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// VULNERABLE: IDOR - No authorization check
exports.updateUser = async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body;

  console.log('Update request:', { id, email, hasPassword: !!password });

  try {
    let query;
    let params;

    if (password) {
      query = `UPDATE users SET email = $1, password = $2 WHERE id = $3 RETURNING id, username, email, role`;
      params = [email, password, id];
    } else {
      query = `UPDATE users SET email = $1 WHERE id = $2 RETURNING id, username, email, role`;
      params = [email, id];
    }

    console.log('Executing query:', query);
    console.log('With params:', params);

    const result = await pool.query(query, params);

    console.log('Query result:', result);

    if (result.rows && result.rows.length > 0) {
      console.log('Update successful');
      res.json({
        success: true,
        message: 'Profile updated successfully',
        user: result.rows[0]
      });
    } else {
      console.log('User not found');
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: error.message
    });
  }
};
