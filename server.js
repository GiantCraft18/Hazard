const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'change-this-to-random-string-in-production';

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// === БАЗА ДАННЫХ ===
const db = new Database('database.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    avatar TEXT,
    status TEXT DEFAULT 'В режиме ожидания',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    contact_user_id TEXT NOT NULL,
    category TEXT DEFAULT 'personal',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(owner_id, contact_user_id)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT,
    description TEXT,
    avatar TEXT,
    icon TEXT,
    owner_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    text TEXT,
    file_name TEXT,
    file_type TEXT,
    file_data TEXT,
    reply_to INTEGER,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    edited INTEGER DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
`);

// === УТИЛИТЫ ===
function generateId() {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let id = '';
  for (let i = 0; i < 10; i++) id += chars.charAt(Math.floor(Math.random() * chars.length));
  return id;
}

function generateUniqueId() {
  let id;
  do { id = generateId(); } while (db.prepare('SELECT 1 FROM users WHERE id = ?').get(id));
  return id;
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
}

// === API: АУТЕНТИФИКАЦИЯ ===

app.post('/api/register', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Имя и пароль обязательны' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

    const id = generateUniqueId();
    const hash = await bcrypt.hash(password, 10);
    const avatar = `https://i.pravatar.cc/150?u=${id}`;

    db.prepare('INSERT INTO users (id, name, password_hash, avatar) VALUES (?, ?, ?, ?)')
      .run(id, name, hash, avatar);

    const token = jwt.sign({ id, name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ id, name, avatar, status: 'Новый пользователь', token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { id, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) return res.status(401).json({ error: 'Неверный ID или пароль' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный ID или пароль' });

    const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ id: user.id, name: user.name, avatar: user.avatar, status: user.status, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// === API: ПОИСК ПОЛЬЗОВАТЕЛЯ ПО ID ===
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, name, avatar, status FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(user);
});

// === API: КОНТАКТЫ ===
app.get('/api/contacts', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id as userId, u.name, u.avatar, u.status,
           c.category, c.created_at as addedAt,
           CASE WHEN u.id IN (SELECT contact_user_id FROM contacts WHERE owner_id = ?)
                THEN 1 ELSE 0 END as isContact
    FROM contacts c
    JOIN users u ON u.id = c.contact_user_id
    WHERE c.owner_id = ?
  `).all(req.user.id, req.user.id);
  res.json(rows);
});

app.post('/api/contacts', authMiddleware, (req, res) => {
  try {
    const { contactUserId, category = 'personal' } = req.body;
    if (!contactUserId) return res.status(400).json({ error: 'Не указан ID' });
    if (contactUserId === req.user.id) return res.status(400).json({ error: 'Нельзя добавить себя' });

    const target = db.prepare('SELECT id, name, avatar, status FROM users WHERE id = ?').get(contactUserId);
    if (!target) return res.status(404).json({ error: 'Пользователь не найден' });

    db.prepare('INSERT OR IGNORE INTO contacts (owner_id, contact_user_id, category) VALUES (?, ?, ?)')
      .run(req.user.id, contactUserId, category);

    // Создаём приватный чат
    const chatId = `private_${[req.user.id, contactUserId].sort().join('_')}`;
    db.prepare(`INSERT OR IGNORE INTO chats (id, type, owner_id, name) VALUES (?, 'private', ?, ?)`)
      .run(chatId, req.user.id, target.name);
    db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.user.id);
    db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, contactUserId);

    res.json({ success: true, contact: target, chatId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// === API: ЧАТЫ (группы и каналы) ===
app.get('/api/chats', authMiddleware, (req, res) => {
  const chats = db.prepare(`
    SELECT c.*, 
           (SELECT COUNT(*) FROM chat_members WHERE chat_id = c.id) as memberCount,
           (SELECT role FROM chat_members WHERE chat_id = c.id AND user_id = ?) as myRole
    FROM chats c
    JOIN chat_members cm ON cm.chat_id = c.id
    WHERE cm.user_id = ?
  `).all(req.user.id, req.user.id);
  res.json(chats);
});

app.post('/api/chats', authMiddleware, (req, res) => {
  try {
    const { type, name, description, memberIds = [], icon, category = 'work' } = req.body;
    if (!name) return res.status(400).json({ error: 'Название обязательно' });
    if (!['group', 'channel'].includes(type)) return res.status(400).json({ error: 'Неверный тип' });

    const chatId = `${type}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    db.prepare(`INSERT INTO chats (id, type, name, description, owner_id, icon) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(chatId, type, name, description || '', req.user.id, icon || (type === 'channel' ? 'fa-bullhorn' : 'fa-users'));

    // Владелец — админ
    db.prepare('INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)')
      .run(chatId, req.user.id, 'creator');

    // Остальные участники
    memberIds.forEach(uid => {
      if (uid !== req.user.id) {
        db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)')
          .run(chatId, uid, 'member');
      }
    });

    res.json({ id: chatId, type, name, description, icon });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/chats/:id/members', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.avatar, u.status, cm.role
    FROM chat_members cm
    JOIN users u ON u.id = cm.user_id
    WHERE cm.chat_id = ?
  `).all(req.params.id);
  res.json(rows);
});

app.post('/api/chats/:id/members', authMiddleware, (req, res) => {
  const { userId } = req.body;
  const myRole = db.prepare('SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!myRole || !['creator', 'admin'].includes(myRole.role)) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)')
    .run(req.params.id, userId, 'member');
  res.json({ success: true });
});

app.delete('/api/chats/:id/members/:userId', authMiddleware, (req, res) => {
  const myRole = db.prepare('SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!myRole || !['creator', 'admin'].includes(myRole.role)) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  if (req.params.userId === req.user.id) {
    return res.status(400).json({ error: 'Нельзя удалить себя' });
  }
  db.prepare('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .run(req.params.id, req.params.userId);
  res.json({ success: true });
});

app.patch('/api/chats/:id', authMiddleware, (req, res) => {
  const myRole = db.prepare('SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!myRole || !['creator', 'admin'].includes(myRole.role)) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  const { name, description, avatar } = req.body;
  db.prepare(`UPDATE chats SET 
    name = COALESCE(?, name),
    description = COALESCE(?, description),
    avatar = COALESCE(?, avatar)
    WHERE id = ?`).run(name, description, avatar, req.params.id);
  res.json({ success: true });
});

// === API: СООБЩЕНИЯ ===
app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT m.*, u.name as senderName, u.avatar as senderAvatar
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    WHERE m.chat_id = ?
    ORDER BY m.created_at ASC
    LIMIT 500
  `).all(req.params.id);
  res.json(rows);
});

app.post('/api/chats/:id/messages', authMiddleware, (req, res) => {
  try {
    const { text, file, replyTo } = req.body;
    const isMember = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!isMember) return res.status(403).json({ error: 'Вы не участник чата' });

    const result = db.prepare(`
      INSERT INTO messages (chat_id, sender_id, text, file_name, file_type, file_data, reply_to)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.params.id, req.user.id, text || null,
      file?.name || null, file?.type || null, file?.data || null,
      replyTo || null
    );

    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(result.lastInsertRowid);
    res.json(msg);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// === HEALTH CHECK ===
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// === SPA FALLBACK ===
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ CP-Messenger server running on http://localhost:${PORT}`);
});
