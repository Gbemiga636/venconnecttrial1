// server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const cron = require('node-cron');
const fs = require('fs');


const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3001;
const MONGO_URI = 'mongodb://localhost:27017/venconnect';
const JWT_SECRET = 'your_secret_key_here';
const JWT_EXPIRY = '7d';

// Upload setup
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `${file.fieldname}-${unique}${ext}`);
  }
});
const upload = multer({ storage });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

// for public HTML view
app.get('/s/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'shop-view.html'));
});

// Database
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true },
  passwordHash: String,
  phone: String,
  location: String,
  shopName: String,
  bio: String,
  shopLogo: String,
  role: { type: String, enum: ['vendor', 'customer'], required: true },
  isAdmin: { type: Boolean, default: false } // ✅ Add this line
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  vendorId: mongoose.Schema.Types.ObjectId,
  name: String,
  price: Number,
  currency: String,
  image: String,
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const videoSchema = new mongoose.Schema({
  vendorId: mongoose.Schema.Types.ObjectId,
  video: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});
const Video = mongoose.model('Video', videoSchema);

const reviewSchema = new mongoose.Schema({
  vendorId: mongoose.Schema.Types.ObjectId,
  customerId: mongoose.Schema.Types.ObjectId,
  customerName: String,
  rating: Number,
  review: String,
  createdAt: { type: Date, default: Date.now }
});
const Review = mongoose.model('Review', reviewSchema);
const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  video: String,
  type: { type: String, enum: ['text', 'product', 'file'], default: 'text' },
  products: [{
    name: String,
    price: Number,
    currency: String,
    image: String
  }],
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
clearedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const kycSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
  name: String,
  dob: String,
  selfie: String,
  idFront: String,
  idBack: String,
  status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  submittedAt: { type: Date, default: Date.now }
});
const KYC = mongoose.model('KYC', kycSchema);
const Message = mongoose.model('Message', messageSchema);
const weeklyLikeLogSchema = new mongoose.Schema({
  vendorId: mongoose.Schema.Types.ObjectId,
  videoId: mongoose.Schema.Types.ObjectId,
  userId: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now }
});

// ✅ Correct: define + register the Report model inline
const reportSchema = new mongoose.Schema({
  reportedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reason: String,
  message: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', reportSchema);
const WeeklyLikeLog = mongoose.model('WeeklyLikeLog', weeklyLikeLogSchema);

const topVendorsSchema = new mongoose.Schema({
  weekStart: Date, // start of the week
  vendors: [{
    vendorId: mongoose.Schema.Types.ObjectId,
    likes: Number
  }]
});
const TopVendors = mongoose.model('TopVendors', topVendorsSchema);
// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).send('Invalid token');
  }
}
const ADMIN_EMAILS = [
  'venconnect@gmail.com',
  'admin2@example.com',
  'admin3@example.com',
  'admin4@example.com'
];

app.post('/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  try {
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });
    if (!user) return res.json({ success: false, message: 'User not found' });

    const isAdmin = ADMIN_EMAILS.includes(user.email);
    const isAdminLogin = isAdmin && password === 'admin';
if (isAdmin && !user.isAdmin) {
  user.isAdmin = true;
  await user.save();
}
    const isPasswordMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordMatch && !isAdminLogin) {
      return res.json({ success: false, message: 'Incorrect password' });
    }

    const payload = {
      id: user._id,
      username: user.username || user.email,
      role: user.role,
      shopName: user.shopName || ''
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 7
    }).json({ success: true, role: user.role, isAdmin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.send('Logged out');
});

// Signup routes
app.post('/signup-vendor', upload.single('shopLogo'), async (req, res) => {
  const { name, shopName, email, password, location, bio } = req.body;
  const shopLogo = req.file?.filename;
  if (!name || !shopName || !email || !password || !location || !bio || !shopLogo) {
    return res.send("All fields are required.");
  }

  try {
    const existing = await User.findOne({ $or: [{ username: shopName }, { email }] });
    if (existing) return res.send("Shop name or email already taken.");

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      username: shopName,
      shopName,
      email,
      passwordHash,
      location,
      bio,
      shopLogo,
      role: 'vendor'
    });

    await newUser.save();
    return res.redirect('/login.html');
  } catch (error) {
    console.error(error);
    res.status(500).send("Something went wrong.");
  }
});

app.post('/signup-customer', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) return res.send("All fields are required.");

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.send("Email already registered.");

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, phone, passwordHash, role: 'customer' });
    await newUser.save();
     return res.redirect('/login.html');
  } catch (error) {
    console.error(error);
    res.status(500).send("Something went wrong.");
  }
});

// GET current user info
app.get('/api/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  res.json({
  id: user._id,
  name: user.name,
  email: user.email,
  phone: user.phone,
  role: user.role,
  shopName: user.shopName,
  bio: user.bio,
  location: user.location || '',
  shopLogo: user.shopLogo || 'default.png'
});
});
// 🔁 Alias for shop-entry.html to use same session
app.get('/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  res.json({
    id: user._id,
    username: user.username,
    role: user.role,
    shopName: user.shopName,
    isAdmin: user.isAdmin
  });
});

// PUT update user info (with logo upload)
app.put('/api/me', requireAuth, upload.single('logo'), async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  const { name, bio, shopName } = req.body;
if (name) user.name = name;
if (bio) user.bio = bio;
if (shopName) user.shopName = shopName;
if (req.file) user.shopLogo = req.file.filename;
if (req.body.location) user.location = req.body.location;

  await user.save();
  res.json({ message: 'Profile updated' });
});

// DELETE current user
app.delete('/api/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).send('User not found');

  // Optional: delete associated products, videos, etc.
  await User.deleteOne({ _id: req.user.id });
  res.clearCookie('token');
  res.send('Account deleted');
});
app.post('/api/kyc', requireAuth, upload.fields([
  { name: 'selfie', maxCount: 1 },
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 }
]), async (req, res) => {
  const { name, dob } = req.body;
  const selfie = req.files?.selfie?.[0]?.filename;
  const idFront = req.files?.idFront?.[0]?.filename;
  const idBack = req.files?.idBack?.[0]?.filename;

  if (!name || !dob || !selfie || !idFront || !idBack) {
    return res.status(400).send('Missing required fields');
  }

  try {
    const existing = await KYC.findOne({ userId: req.user.id });
    if (existing) {
      existing.name = name;
      existing.dob = dob;
      existing.selfie = selfie;
      existing.idFront = idFront;
      existing.idBack = idBack;
      existing.status = 'pending';
      existing.submittedAt = new Date();
      await existing.save();
    } else {
      await KYC.create({
        userId: req.user.id,
        name,
        dob,
        selfie,
        idFront,
        idBack,
        status: 'pending'
      });
    }

    res.send('KYC submitted');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});
app.get('/api/kyc/status', requireAuth, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ userId: req.user.id });
    if (!kyc) return res.json({ status: null });

    res.json({
      status: kyc.status,
      selfieUrl: kyc.selfie ? `/uploads/${kyc.selfie}` : null,
      name: kyc.name,
      dob: kyc.dob
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});
app.get('/api/kyc/:userId', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!ADMIN_EMAILS.includes(user.email)) {
      return res.status(403).send('Forbidden: Admins only');
    }

    const kyc = await KYC.findOne({ userId: req.params.userId });
    if (!kyc) return res.status(404).send('No KYC record');

    res.json({
      name: kyc.name,
      dob: kyc.dob,
      selfie: kyc.selfie,
      idFront: kyc.idFront,
      idBack: kyc.idBack
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching KYC');
  }
});
app.post('/api/report-chat', requireAuth, async (req, res) => {
  let { reportedUserId, reason, message } = req.body;

  if (!reportedUserId) {
    return res.status(400).send('Missing reported user');
  }

  // 💬 Force default values if missing
  if (!reason) reason = 'unspecified';
  if (!message) message = '(no message provided)';

  try {
    await Report.create({
      reporterId: req.user.id,
      reportedUserId,
      reason,
      message
    });
    res.send('Report submitted');
  } catch (err) {
    console.error('Report error:', err);
    res.status(500).send('Failed to submit report');
  }
});
app.get('/api/admin/reports', requireAuth, async (req, res) => {
  const admin = await User.findById(req.user.id);
  if (!ADMIN_EMAILS.includes(admin.email)) return res.status(403).send('Forbidden');

  await Report.updateMany({ read: false }, { $set: { read: true } }); // ✅ NEW

  const reports = await Report.find()
    .sort({ createdAt: -1 })
    .populate('reporterId', 'name email role')
    .populate('reportedUserId', 'name email role shopName');

  res.json(reports);
});
app.patch('/api/admin/reports/:id/resolve', requireAuth, async (req, res) => {
  const admin = await User.findById(req.user.id);
  if (!ADMIN_EMAILS.includes(admin.email)) return res.status(403).send('Forbidden');

  await Report.findByIdAndUpdate(req.params.id, { read: true });
  res.send('Report marked as resolved');
});
app.delete('/api/admin/reports/:id', requireAuth, async (req, res) => {
  const admin = await User.findById(req.user.id);
  if (!ADMIN_EMAILS.includes(admin.email)) return res.status(403).send('Forbidden');

  await Report.findByIdAndDelete(req.params.id);
  res.send('Report deleted');
});
// Shop Routes
app.get('/api/my-shop', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'vendor') return res.status(404).send('No shop');
  res.json({
    shopName: user.shopName,
    bio: user.bio,
    location: user.location,
    shopLogo: user.shopLogo,
    _id: user._id
  });
});

app.post('/api/shops', requireAuth, upload.none(), async (req, res) => {
  const { shopName, bio, location } = req.body;
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'vendor') return res.status(403).send('Only vendors allowed');
  user.shopName = shopName;
  user.bio = bio;
  user.location = location;
  await user.save();
  res.json({ shopName, bio, location, shopLogo: user.shopLogo });
});

app.get('/api/shops', async (req, res) => {
  const query = req.query.search || '';
  const regex = new RegExp(query, 'i');

  try {
    // First, get vendors matching bio/location/shopName
    const vendorsByProfile = await User.find({
  role: 'vendor',
  isAdmin: { $ne: true },
  $or: [
    { shopName: regex },
    { bio: regex },
    { location: regex }
  ]
});

    // Then, get vendor IDs that have products matching the search
    const matchingProducts = await Product.find({ name: regex });
    const productVendorIds = [...new Set(matchingProducts.map(p => p.vendorId.toString()))];

    // Combine vendor IDs from both sources
    const allVendorsMap = new Map();
    vendorsByProfile.forEach(v => allVendorsMap.set(v._id.toString(), v));

   const additionalVendors = await User.find({
  _id: { $in: productVendorIds },
  role: 'vendor',
  isAdmin: { $ne: true }
});
    additionalVendors.forEach(v => allVendorsMap.set(v._id.toString(), v));

    const allVendors = Array.from(allVendorsMap.values());

   const result = await Promise.all(allVendors.map(async v => {
  const kyc = await KYC.findOne({ userId: v._id });
  return {
    _id: v._id,
    shopName: v.shopName,
    shopLogo: v.shopLogo || 'default.png',
    location: v.location,
    bio: v.bio,
    rating: 4.5,
    kycVerified: kyc?.status === 'verified'  // ✅ Add this
  };
}));
res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch shops');
  }
});

cron.schedule('0 0 * * 0', async () => {
  try {
    const res = await fetch('http://localhost:' + PORT + '/api/vendors/weekly-top');
    const json = await res.json();
    console.log('Top vendors refreshed weekly:', json);
  } catch (err) {
    console.error('Weekly cron failed:', err);
  }
});
// Product Routes
app.post('/api/products', requireAuth, upload.single('image'), async (req, res) => {
  const { name, price, currency } = req.body;
  const image = req.file.filename;
  const prod = new Product({ vendorId: req.user.id, name, price, currency, image });
  await prod.save();
  res.json({ success: true });
});

app.get('/api/products/mine', requireAuth, async (req, res) => {
  const products = await Product.find({ vendorId: req.user.id });
  res.json(products);
});
// Update product
app.put('/api/products/:id', requireAuth, upload.single('image'), async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, vendorId: req.user.id });
  if (!product) return res.status(404).send('Product not found');

  const { name, price, currency } = req.body;
  if (name) product.name = name;
  if (price) product.price = price;
  if (currency) product.currency = currency;
  if (req.file) product.image = req.file.filename;

  await product.save();
  res.send('Product updated');
});

// Delete product
app.delete('/api/products/:id', requireAuth, async (req, res) => {
  await Product.deleteOne({ _id: req.params.id, vendorId: req.user.id });
  res.send('Product deleted');
});
// 📌 Add this to server.js
app.get('/api/shop/:id', async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).send('Invalid ID');
  }

  const user = await User.findById(req.params.id);
  if (!user || user.role !== 'vendor') return res.status(404).send('Shop not found');

  const [products, videos, kyc] = await Promise.all([
    Product.find({ vendorId: user._id }),
    Video.find({ vendorId: user._id }),
    KYC.findOne({ userId: user._id })
  ]);

  res.json({
    shop: {
      _id: user._id,
      ownerId: user._id,
      shopName: user.shopName,
      bio: user.bio,
      location: user.location,
      shopLogo: user.shopLogo,
      kycVerified: kyc?.status === 'verified'  // ✅ Add this line
    },
    products,
    videos
  });
});

// Video Routes
app.post('/api/videos', requireAuth, upload.single('video'), async (req, res) => {
  const video = req.file.filename;
  const vid = new Video({ vendorId: req.user.id, video });
  await vid.save();
  res.json({ success: true });
});

app.get('/api/videos/mine', requireAuth, async (req, res) => {
  const videos = await Video.find({ vendorId: req.user.id });
  res.json(videos);
});

app.get('/api/videos/explore', requireAuth, async (req, res) => {
  const videos = await Video.find().sort({ createdAt: -1 }).limit(50);
  res.json(await Promise.all(videos.map(async v => {
    const vendor = await User.findById(v.vendorId);
    const likedByUser = v.likes.includes(req.user.id);
    return {
      _id: v._id,
      video: v.video,
      createdAt: v.createdAt,
      likes: v.likes.length,
      likedByUser,
      vendor: {
        id: vendor._id,
        name: vendor.shopName || vendor.name,
        shopLogo: vendor.shopLogo || null
      }
    };
  })));
});

app.post('/api/videos/:id/like', requireAuth, async (req, res) => {
  const video = await Video.findById(req.params.id);
  if (!video) return res.status(404).send('Video not found');

  const alreadyLiked = video.likes.includes(req.user.id);
  if (!alreadyLiked) {
    video.likes.push(req.user.id);
    await video.save();
await WeeklyLikeLog.create({
  vendorId: video.vendorId,
  videoId: video._id,
  userId: req.user.id,
  createdAt: new Date()
});
  }

  res.json({ liked: true, totalLikes: video.likes.length });
});
app.delete('/api/videos/:id/like', requireAuth, async (req, res) => {
  const video = await Video.findById(req.params.id);
  if (!video) return res.status(404).send('Video not found');

  const wasLiked = video.likes.includes(req.user.id);
  if (wasLiked) {
    video.likes.pull(req.user.id);
    await video.save();
  }

  res.json({ liked: false, totalLikes: video.likes.length });
});

app.delete('/api/videos/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  await Video.deleteOne({ _id: id, vendorId: req.user.id });
  res.send('Deleted');
});
// Get all vendors (with KYC)
app.get('/api/admin/vendors', async (req, res) => {
  const users = await User.find({ role: 'vendor', isAdmin: { $ne: true } });

  const result = await Promise.all(users.map(async user => {
    const kyc = await KYC.findOne({ userId: user._id });

    return {
      _id: user._id,
      shopName: user.shopName,
      shopLogo: user.shopLogo || 'default.png',
      kycVerified: kyc?.status === 'verified',
      kycStatus: kyc?.status || null,
      blocked: user.blocked || false,
      email: user.email || null,           // ✅ Add this
      location: user.location || null,     // ✅ Add this
      bio: user.bio || null                // ✅ Add this
    };
  }));

  res.json(result);
});

app.patch('/api/admin/kyc/:id/approve', async (req, res) => {
  await KYC.updateOne({ userId: req.params.id }, { status: 'verified' });
  res.send('KYC approved');
});

app.patch('/api/admin/kyc/:id/reject', async (req, res) => {
  await KYC.updateOne({ userId: req.params.id }, { status: 'rejected' });
  res.send('KYC rejected');
});

app.patch('/api/admin/block/:id', async (req, res) => {
  const { block } = req.body;
  await User.updateOne({ _id: req.params.id }, { blocked: block });
  res.send('Block status updated');
});

app.delete('/api/admin/delete/:id', async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  await Product.deleteMany({ vendorId: req.params.id });
  await Video.deleteMany({ vendorId: req.params.id });
  await KYC.deleteMany({ userId: req.params.id });
  res.send('Deleted');
});
// Reviews
app.get('/api/reviews/:vendorId', async (req, res) => {
  const reviews = await Review.find({ vendorId: req.params.vendorId }).sort({ createdAt: -1 });
  res.json(reviews);
});

app.post('/api/reviews/:vendorId', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (user.role !== 'customer') return res.status(403).send('Only customers can review');

  const { rating, review } = req.body;
  if (!rating || rating < 1 || rating > 5 || !review) {
    return res.status(400).send('Invalid rating or review');
  }

  const newReview = new Review({
    vendorId: req.params.vendorId,
    customerId: req.user.id,
    customerName: user.name,
    rating,
    review
  });

  await newReview.save();
  res.send('Review submitted');
});
// DELETE /api/messages/:vendorId/delete
app.delete('/api/messages/:vendorId/delete', requireAuth, async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).send('Invalid IDs');

  try {
    await Message.deleteMany({
      _id: { $in: ids },
      $or: [
        { from: req.user.id, to: req.params.vendorId },
        { from: req.params.vendorId, to: req.user.id }
      ]
    });

    res.sendStatus(204);
  } catch (err) {
    console.error('Message deletion failed:', err);
    res.status(500).send('Server error');
  }
});
app.get('/api/inbox', requireAuth, async (req, res) => {
  const userId = new mongoose.Types.ObjectId(req.user.id);

  const messages = await Message.aggregate([
    {
      $match: {
        $or: [
          { to: userId },
          { from: userId }
        ]
      }
    },
    { $sort: { createdAt: -1 } },
    {
      $project: {
        from: 1,
        to: 1,
        text: 1,
        createdAt: 1,
        otherUser: {
          $cond: {
            if: { $eq: ["$from", userId] },
            then: "$to",
            else: "$from"
          }
        }
      }
    },
    {
      $group: {
        _id: "$otherUser",
        lastMessage: { $first: "$text" },
        lastTime: { $first: "$createdAt" }
      }
    },
    { $sort: { lastTime: -1 } }
  ]);

  const enriched = await Promise.all(messages.map(async m => {
    const user = await User.findById(m._id);
    const unreadCount = await Message.countDocuments({
      from: m._id,
      to: req.user.id,
      read: false
    });

    return {
  fromId: m._id,
  fromName: user?.shopName || user?.name || 'Unknown',
  shopLogo: user?.shopLogo ? `/uploads/${user.shopLogo}` : '/uploads/default.png',
  lastMessage: m.lastMessage,
  unreadCount
};
  }));

  res.json(enriched);
});
app.get('/api/vendors/weekly-top', async (req, res) => {
  const now = new Date();
  const startOfWeek = new Date(now);
  startOfWeek.setUTCHours(0, 0, 0, 0);
  startOfWeek.setUTCDate(now.getUTCDate() - now.getUTCDay()); // Sunday

  const oneWeekAgo = new Date(startOfWeek);

  const likes = await WeeklyLikeLog.aggregate([
    { $match: { createdAt: { $gte: oneWeekAgo } } },
    {
      $group: {
        _id: "$vendorId",
        likes: { $sum: 1 }
      }
    },
    { $sort: { likes: -1 } },
    { $limit: 5 }
  ]);

  const vendors = likes.map(v => ({
    vendorId: v._id,
    likes: v.likes
  }));

  await TopVendors.updateOne(
    { weekStart: oneWeekAgo },
    { $set: { vendors } },
    { upsert: true }
  );

  res.json({ message: "Top vendors for the week updated.", vendors });
});
app.get('/api/vendors/top', async (req, res) => {
  const now = new Date();
  const startOfWeek = new Date(now);
  startOfWeek.setUTCHours(0, 0, 0, 0);
  startOfWeek.setUTCDate(now.getUTCDate() - now.getUTCDay()); // Sunday start

  let record = await TopVendors.findOne({ weekStart: startOfWeek });

  // 🔁 If no weekly record exists, fallback to top liked vendors all-time
  if (!record || !record.vendors?.length) {
    const likes = await Video.aggregate([
      {
        $group: {
          _id: "$vendorId",
          likes: { $sum: { $size: "$likes" } }
        }
      },
      { $sort: { likes: -1 } },
      { $limit: 5 }
    ]);

    if (!likes.length) return res.json([]); // Still no vendors, abort

    record = {
      vendors: likes.map(v => ({
        vendorId: v._id,
        likes: v.likes
      }))
    };
  }

  // 🎯 Map vendor info
  const enriched = await Promise.all(
    record.vendors.map(async v => {
      const user = await User.findById(v.vendorId);
      if (!user || user.isAdmin || user.role !== 'vendor') return null;

      const kyc = await KYC.findOne({ userId: user._id });

      return {
        _id: user._id,
        shopName: user.shopName,
        shopLogo: user.shopLogo || 'default.png',
        location: user.location || 'Unknown',
        likes: v.likes || 0,
        kycVerified: kyc?.status === 'verified'
      };
    })
  );

  res.json(enriched.filter(Boolean));
});
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  const messages = await Message.find({
  $or: [
    { from: req.user.id, to: req.params.userId },
    { from: req.params.userId, to: req.user.id }
  ],
  clearedBy: { $ne: req.user.id } // 💡 Exclude cleared
}).sort({ createdAt: 1 });
  res.json(messages.map(m => ({
  _id: m._id,  // ✅ Add this line!
  text: m.text,
  type: m.type,
  products: m.products,
  isMine: m.from.toString() === req.user.id,
  video: m.video ? (m.video.startsWith('/uploads/') ? m.video : `/uploads/${m.video}`) : null,
  createdAt: m.createdAt
})));
});
app.post('/api/messages/:userId', requireAuth, async (req, res) => {
  const { text, video, type, products } = req.body;
if (!text && !video && !products?.length) return res.status(400).send('Empty message');

const msg = new Message({
  from: req.user.id,
  to: req.params.userId,
  text: text || '',
  video: video || '',
  type: type || 'text',
  products: products || [],
  read: false
});

  await msg.save();
  io.to(req.params.userId).emit('new-message', {
  from: req.user.id,
  text,
  video: video || null,
  createdAt: msg.createdAt
});

res.send('Message sent');
});
// 👇 Add this after the existing /api/messages/:userId POST route
app.post('/api/messages/:userId/file', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const filePath = `/uploads/${req.file.filename}`;

  const msg = new Message({
    from: req.user.id,
    to: req.params.userId,
    text: '', // no text, only file
    video: filePath,
    read: false
  });

  await msg.save();
  io.to(req.params.userId).emit('new-message', {
    from: req.user.id,
    text: '',
    video: filePath,
    createdAt: msg.createdAt
  });

  res.json({ fileUrl: filePath });
});
app.patch('/api/messages/:userId/mark-read', requireAuth, async (req, res) => {
  await Message.updateMany(
    { from: req.params.userId, to: req.user.id, read: false },
    { $set: { read: true } }
  );
  res.send('Messages marked as read');
});
app.delete('/api/messages/:vendorId/clear', requireAuth, async (req, res) => {
  try {
    const vendorId = req.params.vendorId;
    const userId = req.user.id;

    await Message.updateMany(
      {
        $or: [
          { from: userId, to: vendorId },
          { from: vendorId, to: userId }
        ],
        clearedBy: { $ne: userId } // not already cleared
      },
      { $addToSet: { clearedBy: userId } }
    );

    res.sendStatus(204);
  } catch (err) {
    console.error('Soft clear failed:', err);
    res.status(500).send('Server error');
  }
});
// Public shop view
io.on('connection', socket => {
  console.log('User connected:', socket.id);

  socket.on('join', userId => {
    socket.join(userId);
  });
socket.on('productUpdated', ({ shopId, excludeSelf }) => {
  if (!shopId) return;
  if (excludeSelf) {
    socket.to(shopId).emit('productUpdated');
  } else {
    io.to(shopId).emit('productUpdated');
  }
});

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

http.listen(PORT, () => {
  console.log(`Socket.IO server running at http://localhost:${PORT}`);
});

