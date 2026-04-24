require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const app = express();
const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const FRONTEND = process.env.FRONTEND_URL || 'http://localhost:3000';

// ─── DB ───────────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/taskforge')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(e => { console.error(e); process.exit(1); });

// ─── Schemas ──────────────────────────────────────────────────────────────────
const OrgSchema = new mongoose.Schema({
  name: { type: String, required: true },
  tenantId: { type: String, default: () => new mongoose.Types.ObjectId().toString() }
}, { timestamps: true });

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, select: false },
  avatar: String,
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Org', required: true },
  role: { type: String, enum: ['owner', 'admin', 'member', 'viewer'], default: 'member' },
  provider: { type: String, default: 'local' },
  googleId: { type: String, sparse: true },
  githubId: { type: String, sparse: true },
  isActive: { type: Boolean, default: true },
  refreshToken: { type: String, select: false }
}, { timestamps: true });

UserSchema.pre('save', async function(next) {
  if (this.isModified('password') && this.password)
    this.password = await bcrypt.hash(this.password, 12);
  next();
});
UserSchema.methods.checkPassword = function(p) { return bcrypt.compare(p, this.password); };
UserSchema.methods.toJSON = function() {
  const o = this.toObject(); delete o.password; delete o.refreshToken; return o;
};

const TaskSchema = new mongoose.Schema({
  title: { type: String, required: true, maxlength: 200 },
  description: { type: String, maxlength: 2000 },
  status: { type: String, enum: ['backlog','todo','in_progress','in_review','done','cancelled'], default: 'todo' },
  priority: { type: String, enum: ['critical','high','medium','low'], default: 'medium' },
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Org', required: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  labels: [String],
  dueDate: Date,
  estimatedHours: Number,
  isDeleted: { type: Boolean, default: false }
}, { timestamps: true });

// Compound indexes for tenant-scoped queries
TaskSchema.index({ organization: 1, status: 1 });
TaskSchema.index({ organization: 1, createdBy: 1 });

const AuditSchema = new mongoose.Schema({
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Org', required: true, index: true },
  actorName: String, actorRole: String,
  action: String,
  resourceType: String, resourceId: mongoose.Schema.Types.ObjectId, resourceTitle: String,
  changes: { before: mongoose.Schema.Types.Mixed, after: mongoose.Schema.Types.Mixed }
}, { timestamps: true });

const Org   = mongoose.model('Org', OrgSchema);
const User  = mongoose.model('User', UserSchema);
const Task  = mongoose.model('Task', TaskSchema);
const Audit = mongoose.model('Audit', AuditSchema);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const makeTokens = (userId, orgId, role) => ({
  accessToken: jwt.sign({ userId, orgId, role }, SECRET, { expiresIn: '7d' }),
  refreshToken: jwt.sign({ userId }, SECRET + '_refresh', { expiresIn: '30d' })
});

const log = async (req, action, type, id, title, changes = {}) => {
  Audit.create({
    organization: req.user.organization,
    actorName: req.user.name, actorRole: req.user.role,
    action, resourceType: type, resourceId: id, resourceTitle: title, changes
  }).catch(() => {});
};

const ROLES = { owner: 4, admin: 3, member: 2, viewer: 1 };
const canEdit = (task, user) =>
  ROLES[user.role] >= ROLES.admin || task.createdBy.toString() === user._id.toString();

// ─── Middleware ───────────────────────────────────────────────────────────────
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Not authenticated' });
  try {
    const { userId } = jwt.verify(token, SECRET);
    const user = await User.findById(userId).populate('organization');
    if (!user?.isActive) return res.status(401).json({ message: 'User not found' });
    req.user = user;
    req.orgId = user.organization._id;
    next();
  } catch {
    // Try refresh inline
    return res.status(401).json({ message: 'Token expired' });
  }
};

const role = (...roles) => (req, res, next) => {
  const min = Math.min(...roles.map(r => ROLES[r] || 99));
  if ((ROLES[req.user.role] || 0) < min)
    return res.status(403).json({ message: `Requires ${roles.join('/')} role` });
  next();
};

// ─── Passport OAuth ───────────────────────────────────────────────────────────
const oauthHandler = (provider) => async (_, __, profile, done) => {
  try {
    const idField = provider + 'Id';
    const email = profile.emails?.[0]?.value || `${provider}_${profile.id}@taskforge.local`;
    let user = await User.findOne({ [idField]: profile.id }).populate('organization');
    if (!user) {
      user = await User.findOne({ email }).populate('organization');
      if (user) { user[idField] = profile.id; await user.save(); }
      else {
        const org = await Org.create({ name: `${profile.displayName || profile.username}'s Workspace` });
        const created = await User.create({
          name: profile.displayName || profile.username || email,
          email, [idField]: profile.id,
          avatar: profile.photos?.[0]?.value,
          provider, organization: org._id, role: 'owner'
        });
        user = await User.findById(created._id).populate('organization');
      }
    }
    done(null, user);
  } catch (e) { done(e); }
};

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== 'your_google_client_id') {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback'
  }, oauthHandler('google')));
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_ID !== 'your_github_client_id') {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:5000/api/auth/github/callback',
    scope: ['user:email']
  }, oauthHandler('github')));
}

const oauthSuccess = async (req, res) => {
  const user = req.user;
  const tokens = makeTokens(user._id, user.organization._id, user.role);
  user.refreshToken = tokens.refreshToken;
  await user.save({ validateBeforeSave: false });
  res.redirect(`${FRONTEND}/auth/callback?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`);
};

// ─── App Setup ────────────────────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND, credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(passport.initialize());
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));

// ─── Auth Routes ──────────────────────────────────────────────────────────────
const A = express.Router();

A.post('/register', async (req, res) => {
  try {
    const { name, email, password, orgName } = req.body;
    if (!name || !email || !password || !orgName)
      return res.status(400).json({ message: 'All fields required' });
    if (await User.findOne({ email }))
      return res.status(409).json({ message: 'Email in use' });
    const org = await Org.create({ name: orgName });
    const user = await User.create({ name, email, password, organization: org._id, role: 'owner' });
    const tokens = makeTokens(user._id, org._id, user.role);
    user.refreshToken = tokens.refreshToken;
    await user.save({ validateBeforeSave: false });
    res.status(201).json({ ...tokens, user: { ...user.toJSON(), organization: org } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

A.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password').populate('organization');
    if (!user || user.provider !== 'local' || !await user.checkPassword(password))
      return res.status(401).json({ message: 'Invalid credentials' });
    if (!user.isActive) return res.status(403).json({ message: 'Account deactivated' });
    const tokens = makeTokens(user._id, user.organization._id, user.role);
    user.refreshToken = tokens.refreshToken;
    await user.save({ validateBeforeSave: false });
    res.json({ ...tokens, user: user.toJSON() });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

A.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'No refresh token' });
    const { userId } = jwt.verify(refreshToken, SECRET + '_refresh');
    const user = await User.findById(userId).select('+refreshToken').populate('organization');
    if (!user || user.refreshToken !== refreshToken)
      return res.status(401).json({ message: 'Invalid refresh token' });
    const tokens = makeTokens(user._id, user.organization._id, user.role);
    user.refreshToken = tokens.refreshToken;
    await user.save({ validateBeforeSave: false });
    res.json(tokens);
  } catch { res.status(401).json({ message: 'Refresh token expired' }); }
});

A.post('/logout', auth, async (req, res) => {
  req.user.refreshToken = undefined;
  await req.user.save({ validateBeforeSave: false });
  res.json({ message: 'Logged out' });
});

A.get('/me', auth, (req, res) => res.json({ user: req.user }));

// OAuth — only register routes if the strategy was actually configured
const notConfigured = (name) => (req, res) =>
  res.status(501).json({ message: `${name} OAuth is not configured on this server` });

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID !== 'your_google_client_id') {
  A.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
  A.get('/google/callback', passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND}/login?error=1` }), oauthSuccess);
} else {
  A.get('/google', notConfigured('Google'));
  A.get('/google/callback', notConfigured('Google'));
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_ID !== 'your_github_client_id') {
  A.get('/github', passport.authenticate('github', { session: false }));
  A.get('/github/callback', passport.authenticate('github', { session: false, failureRedirect: `${FRONTEND}/login?error=1` }), oauthSuccess);
} else {
  A.get('/github', notConfigured('GitHub'));
  A.get('/github/callback', notConfigured('GitHub'));
}

// ─── Task Routes ──────────────────────────────────────────────────────────────
const T = express.Router();
T.use(auth);

T.get('/', async (req, res) => {
  try {
    const { status, priority, page = 1, limit = 25 } = req.query;
    const filter = { organization: req.orgId, isDeleted: false };
    // Members only see their own tasks
    if (ROLES[req.user.role] < ROLES.admin)
      filter.$or = [{ createdBy: req.user._id }, { assignedTo: req.user._id }];
    if (status) filter.status = status;
    if (priority) filter.priority = priority;
    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .populate('createdBy', 'name email avatar')
        .populate('assignedTo', 'name email avatar')
        .sort('-createdAt').skip((page-1)*limit).limit(+limit),
      Task.countDocuments(filter)
    ]);
    res.json({ tasks, total, page: +page });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

T.get('/stats', async (req, res) => {
  try {
    const byStatus = await Task.aggregate([
      { $match: { organization: req.orgId, isDeleted: false } },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    const overdue = await Task.countDocuments({
      organization: req.orgId, isDeleted: false,
      dueDate: { $lt: new Date() }, status: { $nin: ['done','cancelled'] }
    });
    res.json({ byStatus, overdue });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

T.post('/', role('member','admin','owner'), async (req, res) => {
  try {
    const { title, description, status, priority, assignedTo, labels, dueDate, estimatedHours } = req.body;
    if (!title) return res.status(400).json({ message: 'Title required' });
    if (assignedTo) {
      const a = await User.findOne({ _id: assignedTo, organization: req.orgId });
      if (!a) return res.status(400).json({ message: 'Assignee not in org' });
    }
    const task = await Task.create({
      title, description, status, priority, assignedTo, labels, dueDate, estimatedHours,
      organization: req.orgId, createdBy: req.user._id
    });
    await task.populate('createdBy', 'name email avatar');
    await task.populate('assignedTo', 'name email avatar');
    log(req, 'task.created', 'task', task._id, task.title, { after: { title, status, priority } });
    res.status(201).json({ task });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

T.patch('/:id', role('member','admin','owner'), async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, organization: req.orgId, isDeleted: false });
    if (!task) return res.status(404).json({ message: 'Not found' });
    if (!canEdit(task, req.user)) return res.status(403).json({ message: 'Not your task' });
    const fields = ['title','description','status','priority','assignedTo','labels','dueDate','estimatedHours'];
    const before = {}, after = {};
    fields.forEach(f => { if (req.body[f] !== undefined) { before[f] = task[f]; task[f] = req.body[f]; after[f] = req.body[f]; }});
    await task.save();
    await task.populate('createdBy', 'name email avatar');
    await task.populate('assignedTo', 'name email avatar');
    log(req, 'task.updated', 'task', task._id, task.title, { before, after });
    res.json({ task });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

T.delete('/:id', role('member','admin','owner'), async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, organization: req.orgId, isDeleted: false });
    if (!task) return res.status(404).json({ message: 'Not found' });
    if (!canEdit(task, req.user)) return res.status(403).json({ message: 'Not your task' });
    task.isDeleted = true; await task.save();
    log(req, 'task.deleted', 'task', task._id, task.title);
    res.json({ message: 'Deleted' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ─── Org Routes ───────────────────────────────────────────────────────────────
const O = express.Router();
O.use(auth);

O.get('/', (req, res) => res.json({ org: req.user.organization }));

O.patch('/', role('admin','owner'), async (req, res) => {
  try {
    const org = await Org.findByIdAndUpdate(req.orgId, { name: req.body.name }, { new: true });
    res.json({ org });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

O.get('/members', async (req, res) => {
  try {
    const members = await User.find({ organization: req.orgId, isActive: true })
      .select('name email avatar role createdAt provider');
    res.json({ members });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

O.post('/invite', role('admin','owner'), async (req, res) => {
  try {
    const { email, name, role: r = 'member' } = req.body;
    if (!email || !name) return res.status(400).json({ message: 'email and name required' });
    let user = await User.findOne({ email });
    if (user?.organization.toString() === req.orgId.toString())
      return res.status(409).json({ message: 'Already a member' });
    if (user) { user.organization = req.orgId; user.role = r; await user.save(); }
    else {
      user = await User.create({ name, email, password: Math.random().toString(36)+Date.now()+'A1!', organization: req.orgId, role: r });
    }
    log(req, 'user.invited', 'user', user._id, user.name);
    res.status(201).json({ user, note: 'In production, an invite email would be sent.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

O.patch('/members/:id/role', role('admin','owner'), async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id, organization: req.orgId });
    if (!user) return res.status(404).json({ message: 'Not found' });
    if (user.role === 'owner' && req.user.role !== 'owner')
      return res.status(403).json({ message: 'Cannot change owner role' });
    const before = user.role;
    user.role = req.body.role; await user.save();
    log(req, 'user.role_changed', 'user', user._id, user.name, { before: { role: before }, after: { role: req.body.role } });
    res.json({ user });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

O.delete('/members/:id', role('owner'), async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id, organization: req.orgId });
    if (!user || user.role === 'owner') return res.status(400).json({ message: 'Cannot remove owner' });
    user.isActive = false; await user.save();
    log(req, 'user.removed', 'user', user._id, user.name);
    res.json({ message: 'Removed' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

O.get('/audit', role('admin','owner'), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const [logs, total] = await Promise.all([
      Audit.find({ organization: req.orgId }).sort('-createdAt').skip((page-1)*limit).limit(+limit),
      Audit.countDocuments({ organization: req.orgId })
    ]);
    res.json({ logs, total });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ─── Mount & Start ────────────────────────────────────────────────────────────
app.use('/api/auth', A);
app.use('/api/tasks', T);
app.use('/api/org', O);
app.get('/health', (_, res) => res.json({ ok: true }));
app.use((_, res) => res.status(404).json({ message: 'Not found' }));

app.listen(process.env.PORT || 5000, () =>
  console.log(`🚀 TaskForge API on :${process.env.PORT || 5000}`)
);
