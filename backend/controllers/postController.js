const pool = require('../config/database');

exports.getAllPosts = async (req, res) => {
  try {
    const query = `
      SELECT p.*, u.username as author_name 
      FROM posts p 
      JOIN users u ON p.author_id = u.id 
      ORDER BY p.created_at DESC
    `;
    const result = await pool.query(query);
    res.json({
      success: true,
      posts: result.rows
    });
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch posts'
    });
  }
};

exports.createPost = async (req, res) => {
  const { title, content, author_id } = req.body;

  try {
    const query = `
      INSERT INTO posts (title, content, author_id) 
      VALUES ($1, $2, $3) 
      RETURNING *
    `;
    const result = await pool.query(query, [title, content, author_id]);
    
    res.json({
      success: true,
      message: 'Post created successfully',
      post: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create post'
    });
  }
};

// VULNERABLE: SQL Injection
exports.searchPosts = async (req, res) => {
  const { q } = req.query;

  try {
    const query = `
      SELECT p.*, u.username as author_name 
      FROM posts p 
      JOIN users u ON p.author_id = u.id 
      WHERE p.title LIKE '%${q}%' OR p.content LIKE '%${q}%'
      ORDER BY p.created_at DESC
    `;
    
    console.log('Search query:', query);
    
    const result = await pool.query(query);
    res.json({
      success: true,
      posts: result.rows
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({
      success: false,
      message: 'Search failed',
      error: error.message
    });
  }
};
