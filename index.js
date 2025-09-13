const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const port = 5000;

// Multer Configuration
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['model/gltf-binary', 'application/octet-stream', 'text/plain', 'image/png', 'image/jpeg', 'model/vnd.fbx'];
  const allowedExtensions = ['.glb', '.obj', '.mtl', '.png', '.jpg', '.jpeg', '.fbx'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowedTypes.includes(file.mimetype) && allowedExtensions.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only .glb, .obj, .mtl, .png, .jpg, .jpeg, and .fbx files are allowed.'), false);
  }
};
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// Middleware
app.use(cors({ origin: ['http://localhost:5173', 'https://hkmu-3d-model-hub.vercel.app'] }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB (HKMU 3D Model)'))
  .catch(err => console.error('MongoDB connection error:', err));

// Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  nickname: { type: String, default: '' },
  icon: { type: String, default: '' },
});
const User = mongoose.model('User', userSchema);

// Model Schema
const modelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  fileType: { type: String, required: true, enum: ['obj', 'fbx', 'glb'] },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  filePath: { type: String, required: true },
  previewPath: { type: String, required: true },
  fileSize: { type: Number, default: 0 },
  visits: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  downloads: { type: Number, default: 0 },
});
const Model = mongoose.model('Model', modelSchema);

// Comment Schema
const commentSchema = new mongoose.Schema({
  model: { type: mongoose.Schema.Types.ObjectId, ref: 'Model', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Comment = mongoose.model('Comment', commentSchema);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register Route
app.post('/api/register', async (req, res) => {
  const { username, email, password, nickname } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }
  if (!email.endsWith('@hkmu.edu.hk') && !email.endsWith('@live.hkmu.edu.hk')) {
    return res.status(400).json({ error: 'Only HKMU email addresses (@hkmu.edu.hk or @live.hkmu.edu.hk) are allowed' });
  }
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({
        error: existingUser.username === username ? 'Username already taken' : 'Email already registered'
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      nickname: nickname || '',
    });
    await user.save();
    res.status(201).json({ message: 'User registered successfully. You can now log in.' });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(400).json({ error: 'User registration failed', details: error.message });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { identifier, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({
      token,
      user: { id: user._id, username: user.username, email: user.email, nickname: user.nickname || '', icon: user.icon || '', role: user.role },
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

// Update Profile
app.post('/api/profile', authenticateToken, upload.single('icon'), async (req, res) => {
  const { nickname } = req.body;
  const file = req.file;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (nickname !== undefined) user.nickname = nickname;

    if (file) {
      const fileName = `icons/${req.user.id}/${Date.now()}_${file.originalname}`;
      const { data, error } = await supabase.storage
        .from('models')
        .upload(fileName, file.buffer, { contentType: file.mimetype });
      if (error) throw error;
      user.icon = `${process.env.SUPABASE_URL}/storage/v1/object/public/models/${fileName}`;
    }

    await user.save();
    res.json({
      message: 'Profile updated successfully',
      user: { id: user._id, username: user.username, email: user.email, nickname: user.nickname || '', icon: user.icon || '', role: user.role },
    });
  } catch (error) {
    console.error('Profile update error:', error.message);
    res.status(500).json({ error: 'Profile update failed', details: error.message });
  }
});

// Upload Model
app.post('/api/models', authenticateToken, upload.array('file', 3), async (req, res) => {
  const { name, description, fileType } = req.body;
  const files = req.files;
  if (!files || files.length === 0) return res.status(400).json({ error: 'No files provided' });
  if (!name || !fileType) return res.status(400).json({ error: 'Name and fileType are required' });

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const modelFile = files.find(f => f.originalname.match(/\.(obj|fbx|glb)$/i));
    const previewFile = files.find(f => f.originalname.match(/\.(png|jpg|jpeg)$/i));
    if (!modelFile) return res.status(400).json({ error: 'Model file (.obj, .fbx, .glb) required' });
    if (!previewFile) return res.status(400).json({ error: 'Preview image (.png, .jpg, .jpeg) required' });

    const modelFileName = `models/${req.user.id}/${name}.${fileType}`;
    const previewFileName = `models/${req.user.id}/${name}.png`;
    const uploadPromises = [
      supabase.storage.from('models').upload(modelFileName, modelFile.buffer, { contentType: modelFile.mimetype }),
      supabase.storage.from('models').upload(previewFileName, previewFile.buffer, { contentType: 'image/png' }),
    ];

    const mtlFile = files.find(f => f.originalname.match(/\.mtl$/i));
    if (mtlFile) {
      const mtlFileName = `models/${req.user.id}/${name}.mtl`;
      uploadPromises.push(
        supabase.storage.from('models').upload(mtlFileName, mtlFile.buffer, { contentType: 'text/plain' })
      );
    }

    const results = await Promise.all(uploadPromises);
    const errors = results.filter(r => r.error);
    if (errors.length > 0) throw errors[0].error;

    const model = new Model({
      name,
      description: description || '',
      fileType: fileType.toLowerCase(),
      owner: req.user.id,
      filePath: modelFileName,
      previewPath: previewFileName,
      fileSize: modelFile.size,
      likes: [],
    });
    await model.save();

    res.json({ message: 'Model uploaded successfully', model });
  } catch (error) {
    console.error('Upload error:', error.message);
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
});

// Get All Models
app.get('/api/models', async (req, res) => {
  try {
    const models = await Model.find().populate('owner', 'username nickname');
    res.json(models);
  } catch (error) {
    console.error('Fetch models error:', error.message);
    res.status(500).json({ error: 'Failed to fetch models', details: error.message });
  }
});

// Get Single Model by ID
app.get('/api/models/:id', async (req, res) => {
  try {
    const model = await Model.findById(req.params.id).populate('owner', 'username nickname');
    if (!model) return res.status(404).json({ error: 'Model not found' });
    model.visits = (model.visits || 0) + 1;
    await model.save();
    res.json(model);
  } catch (error) {
    console.error('Fetch model error:', error.message);
    res.status(500).json({ error: 'Failed to fetch model', details: error.message });
  }
});

// Get User's Models
app.get('/api/user/models', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const models = await Model.find({ owner: req.user.id });
    res.json(models);
  } catch (error) {
    console.error('Fetch user models error:', error.message);
    res.status(500).json({ error: 'Failed to fetch user models', details: error.message });
  }
});

// Update Model
app.put('/api/models/:id', authenticateToken, upload.array('file', 3), async (req, res) => {
  const { id } = req.params;
  const { name, description, fileType } = req.body;
  const files = req.files;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const model = await Model.findById(id);
    if (!model) return res.status(404).json({ error: 'Model not found' });
    if (model.owner.toString() !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    if (name) model.name = name;
    if (description) model.description = description;
    if (fileType) model.fileType = fileType.toLowerCase();

    if (files.length > 0) {
      const modelFile = files.find(f => f.originalname.match(/\.(obj|fbx|glb)$/i));
      const previewFile = files.find(f => f.originalname.match(/\.(png|jpg|jpeg)$/i));
      const mtlFile = files.find(f => f.originalname.match(/\.mtl$/i));

      if (modelFile) {
        const modelFileName = `models/${req.user.id}/${name || model.name}.${model.fileType}`;
        const { error } = await supabase.storage.from('models').upload(modelFileName, modelFile.buffer, {
          contentType: modelFile.mimetype,
          upsert: true,
        });
        if (error) throw error;
        model.filePath = modelFileName;
        model.fileSize = modelFile.size;
      }

      if (previewFile) {
        const previewFileName = `models/${req.user.id}/${name || model.name}.png`;
        const { error } = await supabase.storage.from('models').upload(previewFileName, previewFile.buffer, {
          contentType: 'image/png',
          upsert: true,
        });
        if (error) throw error;
        model.previewPath = previewFileName;
      }

      if (mtlFile) {
        const mtlFileName = `models/${req.user.id}/${name || model.name}.mtl`;
        const { error } = await supabase.storage.from('models').upload(mtlFileName, mtlFile.buffer, {
          contentType: 'text/plain',
          upsert: true,
        });
        if (error) throw error;
      }
    }

    await model.save();
    res.json({ message: 'Model updated successfully', model });
  } catch (error) {
    console.error('Update model error:', error.message);
    res.status(500).json({ error: 'Update failed', details: error.message });
  }
});

// Delete Model
app.delete('/api/models/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const model = await Model.findById(id);
    if (!model) return res.status(404).json({ error: 'Model not found' });
    if (model.owner.toString() !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const deletePromises = [
      supabase.storage.from('models').remove([model.filePath]),
      supabase.storage.from('models').remove([model.previewPath]),
    ];
    if (model.fileType === 'obj') {
      deletePromises.push(supabase.storage.from('models').remove([model.filePath.replace('.obj', '.mtl')]));
    }
    await Promise.all(deletePromises);

    await Comment.deleteMany({ model: id });
    await model.deleteOne();
    res.json({ message: 'Model deleted successfully' });
  } catch (error) {
    console.error('Delete model error:', error.message);
    res.status(500).json({ error: 'Deletion failed', details: error.message });
  }
});

// Download Model
app.get('/api/models/download/:fileName', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { fileName } = req.params;
    const model = await Model.findOne({ filePath: { $regex: `${fileName}$`, $options: 'i' } });
    if (!model) {
      console.error(`Model not found for fileName: ${fileName}`);
      return res.status(404).json({ error: 'Model not found' });
    }
    const { data, error } = await supabase.storage
      .from('models')
      .download(model.filePath);
    if (error) {
      console.error(`Supabase download error: ${error.message}`);
      throw error;
    }
    model.downloads = (model.downloads || 0) + 1;
    await model.save();
    const arrayBuffer = await data.arrayBuffer();
    res.setHeader('Content-Type', fileName.endsWith('.glb') ? 'model/gltf-binary' : fileName.endsWith('.png') ? 'image/png' : fileName.endsWith('.jpg') || fileName.endsWith('.jpeg') ? 'image/jpeg' : fileName.endsWith('.fbx') ? 'model/vnd.fbx' : 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(Buffer.from(arrayBuffer));
  } catch (error) {
    console.error('Download endpoint error:', error.message);
    res.status(500).json({ error: 'Download failed', details: error.message });
  }
});

// Like Model
app.post('/api/models/:id/like', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const model = await Model.findById(req.params.id);
    if (!model) return res.status(404).json({ error: 'Model not found' });
    if (!Array.isArray(model.likes)) model.likes = [];
    if (model.likes.includes(req.user.id)) {
      model.likes = model.likes.filter(userId => userId.toString() !== req.user.id);
    } else {
      model.likes.push(req.user.id);
    }
    await model.save();
    res.json({ message: 'Like updated', likes: model.likes });
  } catch (error) {
    console.error('Like endpoint error:', error.message);
    res.status(500).json({ error: 'Like failed', details: error.message });
  }
});

// Post Comment
app.post('/api/models/:id/comments', authenticateToken, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Comment content is required' });
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const model = await Model.findById(req.params.id);
    if (!model) return res.status(400).json({ error: 'Model not found' });
    const comment = new Comment({
      model: req.params.id,
      user: req.user.id,
      content,
    });
    await comment.save();
    res.status(201).json({ message: 'Comment posted', comment });
  } catch (error) {
    console.error('Comment endpoint error:', error.message);
    res.status(500).json({ error: 'Comment failed', details: error.message });
  }
});

// Get Comments
app.get('/api/models/:id/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ model: req.params.id }).populate('user', 'username nickname');
    res.json(comments);
  } catch (error) {
    console.error('Fetch comments error:', error.message);
    res.status(500).json({ error: 'Failed to fetch comments', details: error.message });
  }
});

// Contact Form
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  console.log('Received contact form submission:', { name, email, message });
  res.status(200).json({ message: 'Form submission received!' });
});

// Admin Routes - Protected for admins only
const authenticateAdmin = (req, res, next) => {
  authenticateToken(req, res, () => {
    User.findById(req.user.id).then(user => {
      if (user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
      }
      req.user = user;
      next();
    }).catch(err => res.status(500).json({ error: 'Server error' }));
  });
};

// Get All Users (Admin Only)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find({}, 'username email nickname icon role').populate('icon'); // Exclude password
    res.json(users);
  } catch (error) {
    console.error('Fetch users error:', error.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update User (Admin Only)
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, nickname, icon, role } = req.body;
  try {
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (username) user.username = username;
    if (nickname !== undefined) user.nickname = nickname;
    if (icon) user.icon = icon;
    if (role) user.role = role;
    await user.save();
    res.json({ message: 'User updated successfully', user });
  } catch (error) {
    console.error('Update user error:', error.message);
    res.status(500).json({ error: 'Update failed' });
  }
});

// Delete User (Admin Only)
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await user.deleteOne();
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error.message);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Get All Models (Admin Only)
app.get('/api/admin/models', authenticateAdmin, async (req, res) => {
  try {
    const models = await Model.find().populate('owner', 'username nickname');
    res.json(models);
  } catch (error) {
    console.error('Fetch models error:', error.message);
    res.status(500).json({ error: 'Failed to fetch models' });
  }
});

// Update Model (Admin Only)
app.put('/api/admin/models/:id', authenticateAdmin, upload.array('file', 3), async (req, res) => {
  const { id } = req.params;
  const { name, description, fileType } = req.body;
  const files = req.files;
  try {
    const model = await Model.findById(id);
    if (!model) return res.status(404).json({ error: 'Model not found' });

    if (name) model.name = name;
    if (description) model.description = description;
    if (fileType) model.fileType = fileType.toLowerCase();

    if (files && files.length > 0) {
      const modelFile = files.find(f => f.originalname.match(/\.(obj|fbx|glb)$/i));
      const previewFile = files.find(f => f.originalname.match(/\.(png|jpg|jpeg)$/i));
      const mtlFile = files.find(f => f.originalname.match(/\.mtl$/i));

      if (modelFile) {
        const modelFileName = `models/${model.owner}/${name || model.name}.${model.fileType}`;
        const { error: uploadError } = await supabase.storage.from('models').upload(modelFileName, modelFile.buffer, {
          contentType: modelFile.mimetype,
          upsert: true,
        });
        if (uploadError) throw uploadError;
        model.filePath = modelFileName;
        model.fileSize = modelFile.size;
      }

      if (previewFile) {
        const previewFileName = `models/${model.owner}/${name || model.name}.png`;
        const { error: uploadError } = await supabase.storage.from('models').upload(previewFileName, previewFile.buffer, {
          contentType: 'image/png',
          upsert: true,
        });
        if (uploadError) throw uploadError;
        model.previewPath = previewFileName;
      }

      if (mtlFile) {
        const mtlFileName = `models/${model.owner}/${name || model.name}.mtl`;
        const { error: uploadError } = await supabase.storage.from('models').upload(mtlFileName, mtlFile.buffer, {
          contentType: 'text/plain',
          upsert: true,
        });
        if (uploadError) throw uploadError;
      }
    }

    await model.save();
    res.json({ message: 'Model updated successfully', model });
  } catch (error) {
    console.error('Update model error:', error.message);
    res.status(500).json({ error: 'Update failed' });
  }
});

// Delete Model (Admin Only)
app.delete('/api/admin/models/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const model = await Model.findById(id);
    if (!model) return res.status(404).json({ error: 'Model not found' });

    const deletePromises = [
      supabase.storage.from('models').remove([model.filePath]),
      supabase.storage.from('models').remove([model.previewPath]),
    ];
    if (model.fileType === 'obj') {
      deletePromises.push(supabase.storage.from('models').remove([model.filePath.replace('.obj', '.mtl')]));
    }
    await Promise.all(deletePromises);

    await Comment.deleteMany({ model: id });
    await model.deleteOne();
    res.json({ message: 'Model deleted successfully' });
  } catch (error) {
    console.error('Delete model error:', error.message);
    res.status(500).json({ error: 'Delete failed' });
  }
});


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});