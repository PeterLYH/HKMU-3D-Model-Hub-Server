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
app.use(cors({ origin: 'http://localhost:5173' }));
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
});
const Model = mongoose.model('Model', modelSchema);

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
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, nickname: nickname || '' });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
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
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({
      token,
      user: { id: user._id, username: user.username, email: user.email, nickname: user.nickname || '', icon: user.icon || '', role: user.role },
    });
  } catch (error) {
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
    });
    await model.save();

    res.json({ message: 'Model uploaded successfully', model });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
});

// Get All Models
app.get('/api/models', async (req, res) => {
  try {
    const models = await Model.find().populate('owner', 'username nickname');
    res.json(models);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch models', details: error.message });
  }
});

// Get User's Models
app.get('/api/user/models', authenticateToken, async (req, res) => {
  try {
    const models = await Model.find({ owner: req.user.id });
    res.json(models);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user models', details: error.message });
  }
});

// Update Model
app.put('/api/models/:id', authenticateToken, upload.array('file', 3), async (req, res) => {
  const { id } = req.params;
  const { name, description, fileType } = req.body;
  const files = req.files;
  try {
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
    res.status(500).json({ error: 'Update failed', details: error.message });
  }
});

// Delete Model
app.delete('/api/models/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
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

    await model.deleteOne();
    res.json({ message: 'Model deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Deletion failed', details: error.message });
  }
});

// Download Model
app.get('/api/models/:fileName', authenticateToken, async (req, res) => {
  try {
    const { fileName } = req.params;
    const { data, error } = await supabase.storage
      .from('models')
      .download(`models/${req.user.id}/${fileName}`);
    if (error) throw error;
    const arrayBuffer = await data.arrayBuffer();
    res.setHeader('Content-Type', fileName.endsWith('.glb') ? 'model/gltf-binary' : fileName.endsWith('.png') ? 'image/png' : fileName.endsWith('.jpg') || fileName.endsWith('.jpeg') ? 'image/jpeg' : fileName.endsWith('.fbx') ? 'model/vnd.fbx' : 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(Buffer.from(arrayBuffer));
  } catch (error) {
    res.status(500).json({ error: 'Download failed', details: error.message });
  }
});

// Contact Form
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  console.log('Received contact form submission:', { name, email, message });
  res.status(200).json({ message: 'Form submission received!' });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});