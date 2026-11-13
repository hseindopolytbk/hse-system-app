import crypto from 'crypto';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import JSZip from 'jszip';
import multer from 'multer';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import db, {
  DOCS_UPLOAD_PATH,
  PHOTOS_UPLOAD_PATH,
  hashPassword,
  initDatabase,
} from './src/server/db.js';
import type { User, UserRole } from './src/types/hse.js';

dotenv.config();
initDatabase();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'hse-system-industrial-secret-2026';

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Static uploads serving
app.use('/uploads/docs', express.static(DOCS_UPLOAD_PATH));
app.use('/uploads/photos', express.static(PHOTOS_UPLOAD_PATH));

// Multer setups
const docStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, DOCS_UPLOAD_PATH),
  filename: (_req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e6)}-${safeName}`);
  },
});
const uploadDocs = multer({ storage: docStorage, limits: { fileSize: 50 * 1024 * 1024 } });

const photoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, PHOTOS_UPLOAD_PATH),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `photo-${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`);
  },
});
const uploadPhoto = multer({ storage: photoStorage, limits: { fileSize: 15 * 1024 * 1024 } });

// Token helpers
function signSessionToken(user: User): string {
  const payload = Buffer.from(
    JSON.stringify({ id: user.id, username: user.username, role: user.role, full_name: user.full_name })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySessionToken(token: string | undefined): { id: number; username: string; role: UserRole; full_name: string } | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const dbUser = db.prepare('SELECT id, username, role, full_name, is_active FROM users WHERE id = ?').get(parsed.id) as
      | (User & { is_active: number })
      | undefined;
    if (!dbUser || !dbUser.is_active) return null;
    return { id: dbUser.id, username: dbUser.username, role: dbUser.role, full_name: dbUser.full_name };
  } catch {
    return null;
  }
}

interface CurrentUserInfo {
  id: number | null;
  username: string;
  role: UserRole;
  full_name: string;
  isAuthenticated: boolean;
}

declare global {
  namespace Express {
    interface Request {
      currentUser?: CurrentUserInfo;
    }
  }
}

function getActor(req: Request): CurrentUserInfo {
  return (
    req.currentUser || {
      id: null,
      username: 'guest',
      role: 'VIEWER',
      full_name: 'Tamu / Pengunjung',
      isAuthenticated: false,
    }
  );
}

function attachUser(req: Request, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.headers['x-session-token'] as string | undefined);
  const verified = verifySessionToken(token);
  if (verified) {
    req.currentUser = { ...verified, isAuthenticated: true };
  } else {
    // Accessible without login: default guest capability on field flows, restricted admin routes
    req.currentUser = {
      id: null,
      username: 'guest',
      role: 'VIEWER',
      full_name: 'Tamu / Pengunjung',
      isAuthenticated: false,
    };
  }
  next();
}

function requireRole(roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = getActor(req);
    if (!roles.includes(u.role)) {
      return res.status(403).json({
        error: `Akses ditolak. Fitur ini memerlukan hak akses ${roles.join(' atau ')}.`,
      });
    }
    next();
  };
}

function writeAudit(actorName: string, actorRole: string, action: string, entityType: string, entityId: string, summary: string) {
  db.prepare(`
    INSERT INTO audit_logs (actor_name, actor_role, action, entity_type, entity_id, summary)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(actorName, actorRole, action, entityType, entityId, summary);
}

app.use('/api', attachUser);

// ================= AUTH & USERS =================
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body as { username?: string; password?: string };
  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi.' });
  }
  const user = db
    .prepare('SELECT id, username, password, full_name, role, department, is_active, created_at FROM users WHERE LOWER(username) = LOWER(?)')
    .get(username.trim()) as (User & { password: string }) | undefined;

  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Username atau password salah.' });
  }
  if (!user.is_active) {
    return res.status(403).json({ error: 'Akun pengguna dinonaktifkan oleh Administrator.' });
  }

  const safeUser: User = {
    id: user.id,
    username: user.username,
    full_name: user.full_name,
    role: user.role,
    department: user.department,
    is_active: user.is_active,
    created_at: user.created_at,
  };
  const token = signSessionToken(safeUser);
  writeAudit(safeUser.full_name, safeUser.role, 'LOGIN', 'USER', String(safeUser.id), `${safeUser.full_name} login sebagai ${safeUser.role}.`);
  res.json({ token, user: safeUser });
});

app.get('/api/auth/me', (req, res) => {
  const u = getActor(req);
  if (!u.isAuthenticated || !u.id) {
    return res.json({ user: null });
  }
  const dbUser = db
    .prepare('SELECT id, username, full_name, role, department, is_active, created_at FROM users WHERE id = ?')
    .get(u.id);
  res.json({ user: dbUser || null });
});

app.get('/api/users', requireRole(['ADMIN']), (_req, res) => {
  const users = db.prepare('SELECT id, username, full_name, role, department, is_active, created_at FROM users ORDER BY id ASC').all();
  res.json(users);
});

app.post('/api/users', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const { username, password, full_name, role, department } = req.body;
  if (!username || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Semua field wajib diisi.' });
  }
  try {
    const info = db
      .prepare('INSERT INTO users (username, password, full_name, role, department, is_active) VALUES (?, ?, ?, ?, ?, 1)')
      .run(username.trim(), hashPassword(password), full_name.trim(), role, department || 'HSE');
    writeAudit(actor.full_name, actor.role, 'CREATE', 'USER', String(info.lastInsertRowid), `Menambahkan pengguna ${full_name} (${role}).`);
    const created = db.prepare('SELECT id, username, full_name, role, department, is_active, created_at FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json(created);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username sudah terdaftar.' });
    }
    res.status(500).json({ error: 'Gagal membuat pengguna.' });
  }
});

app.patch('/api/users/:id', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const { full_name, role, department, is_active, password } = req.body;
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as User | undefined;
  if (!existing) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });

  db.prepare(`
    UPDATE users
    SET full_name = ?, role = ?, department = ?, is_active = ?
    WHERE id = ?
  `).run(
    full_name ?? existing.full_name,
    role ?? existing.role,
    department ?? existing.department,
    is_active !== undefined ? (is_active ? 1 : 0) : existing.is_active,
    id
  );
  if (password && String(password).trim().length > 0) {
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(String(password)), id);
  }
  writeAudit(actor.full_name, actor.role, 'UPDATE', 'USER', String(id), `Memperbarui data pengguna ${full_name ?? existing.full_name}.`);
  const updated = db.prepare('SELECT id, username, full_name, role, department, is_active, created_at FROM users WHERE id = ?').get(id);
  res.json(updated);
});

app.delete('/api/users/:id', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  if (actor.id === id) {
    return res.status(400).json({ error: 'Tidak dapat menghapus akun yang sedang digunakan.' });
  }
  const existing = db.prepare('SELECT full_name FROM users WHERE id = ?').get(id) as { full_name: string } | undefined;
  if (!existing) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  writeAudit(actor.full_name, actor.role, 'DELETE', 'USER', String(id), `Menghapus pengguna ${existing.full_name}.`);
  res.json({ success: true });
});

// ================= DASHBOARD & NOTIFICATIONS & AUDIT =================
app.get('/api/dashboard', (_req, res) => {
  const totalEquipment = (db.prepare('SELECT COUNT(*) as c FROM equipment').get() as { c: number }).c;
  const activeEquipment = (db.prepare("SELECT COUNT(*) as c FROM equipment WHERE status = 'ACTIVE'").get() as { c: number }).c;
  const totalInspections = (db.prepare('SELECT COUNT(*) as c FROM inspections').get() as { c: number }).c;
  const totalDocuments = (db.prepare('SELECT COUNT(*) as c FROM documents').get() as { c: number }).c;
  const totalFolders = (db.prepare('SELECT COUNT(*) as c FROM folders').get() as { c: number }).c;
  const unreadNotifications = (db.prepare('SELECT COUNT(*) as c FROM notifications WHERE is_read = 0').get() as { c: number }).c;

  // Latest status per active equipment
  const latestRows = db.prepare(`
    SELECT e.id, e.category_id, c.name as category_name,
      (SELECT overall_status FROM inspections i WHERE i.equipment_id = e.id ORDER BY i.inspected_at DESC, i.id DESC LIMIT 1) as latest_status
    FROM equipment e
    JOIN equipment_categories c ON c.id = e.category_id
  `).all() as Array<{ id: number; category_id: number; category_name: string; latest_status: string | null }>;

  let inspectedEquipmentCount = 0;
  let uninspectedEquipmentCount = 0;
  let normalCount = 0;
  let attentionCount = 0;
  let abnormalCount = 0;

  const catMap = new Map<
    number,
    { category_id: number; category_name: string; total: number; inspected: number; uninspected: number; normal: number; attention: number; abnormal: number }
  >();

  const allCats = db.prepare('SELECT id, name FROM equipment_categories ORDER BY id ASC').all() as Array<{ id: number; name: string }>;
  for (const cat of allCats) {
    catMap.set(cat.id, {
      category_id: cat.id,
      category_name: cat.name,
      total: 0,
      inspected: 0,
      uninspected: 0,
      normal: 0,
      attention: 0,
      abnormal: 0,
    });
  }

  for (const row of latestRows) {
    const entry = catMap.get(row.category_id);
    if (entry) entry.total++;
    if (!row.latest_status) {
      uninspectedEquipmentCount++;
      if (entry) entry.uninspected++;
    } else {
      inspectedEquipmentCount++;
      if (entry) entry.inspected++;
      if (row.latest_status === 'NORMAL') {
        normalCount++;
        if (entry) entry.normal++;
      } else if (row.latest_status === 'ATTENTION') {
        attentionCount++;
        if (entry) entry.attention++;
      } else if (row.latest_status === 'ABNORMAL') {
        abnormalCount++;
        if (entry) entry.abnormal++;
      }
    }
  }

  const recentInspections = db.prepare(`
    SELECT i.*, e.asset_number, e.name as equipment_name, e.location, c.name as category_name
    FROM inspections i
    JOIN equipment e ON e.id = i.equipment_id
    JOIN equipment_categories c ON c.id = e.category_id
    ORDER BY i.inspected_at DESC, i.id DESC
    LIMIT 10
  `).all();

  res.json({
    total_equipment: totalEquipment,
    active_equipment: activeEquipment,
    inspected_equipment_count: inspectedEquipmentCount,
    uninspected_equipment_count: uninspectedEquipmentCount,
    total_inspections: totalInspections,
    abnormal_count: abnormalCount,
    attention_count: attentionCount,
    normal_count: normalCount,
    total_documents: totalDocuments,
    total_folders: totalFolders,
    unread_notifications: unreadNotifications,
    category_breakdown: Array.from(catMap.values()),
    recent_inspections: recentInspections,
  });
});

app.get('/api/notifications', (_req, res) => {
  const rows = db.prepare('SELECT * FROM notifications ORDER BY created_at DESC, id DESC LIMIT 50').all();
  res.json(rows);
});

app.patch('/api/notifications/:id/read', (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(Number(req.params.id));
  res.json({ success: true });
});

app.post('/api/notifications/read-all', (_req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1').run();
  res.json({ success: true });
});

app.get('/api/audit-logs', (_req, res) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 200').all();
  res.json(logs);
});

// ================= MENU 1: DOKUMEN (FOLDERS & FILES) =================
function canAccess(accessRole: string, userRole: UserRole): boolean {
  if (accessRole === 'ALL') return true;
  if (userRole === 'ADMIN') return true;
  if (accessRole === 'INSPECTOR' && userRole === 'INSPECTOR') return true;
  return false;
}

app.get('/api/folders', (req, res) => {
  const u = getActor(req);
  const sortBy = (req.query.sortBy as string) || 'sort_order';
  let orderClause = 'sort_order ASC, name ASC';
  if (sortBy === 'name') orderClause = 'name ASC';
  if (sortBy === 'date') orderClause = 'created_at DESC';

  const folders = db.prepare(`SELECT * FROM folders ORDER BY ${orderClause}`).all() as Array<{ access_role: string }>;
  res.json(folders.filter((f) => canAccess(f.access_role, u.role)));
});

app.post('/api/folders', (req, res) => {
  const actor = getActor(req);
  const { name, parent_id, access_role } = req.body;
  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'Nama folder wajib diisi.' });
  }
  const maxOrder = (
    db
      .prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM folders WHERE parent_id IS ?')
      .get(parent_id || null) as { m: number }
  ).m;

  const info = db
    .prepare('INSERT INTO folders (name, parent_id, sort_order, access_role, created_by) VALUES (?, ?, ?, ?, ?)')
    .run(String(name).trim(), parent_id || null, maxOrder + 1, access_role || 'ALL', actor.full_name);

  writeAudit(actor.full_name, actor.role, 'CREATE', 'FOLDER', String(info.lastInsertRowid), `Membuat folder "${String(name).trim()}".`);
  const created = db.prepare('SELECT * FROM folders WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json(created);
});

app.patch('/api/folders/:id', (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM folders WHERE id = ?').get(id) as
    | { id: number; name: string; parent_id: number | null; sort_order: number; access_role: string }
    | undefined;
  if (!existing) return res.status(404).json({ error: 'Folder tidak ditemukan.' });

  const { name, parent_id, sort_order, access_role } = req.body;
  if (parent_id !== undefined && Number(parent_id) === id) {
    return res.status(400).json({ error: 'Folder tidak dapat dipindahkan ke dalam dirinya sendiri.' });
  }

  db.prepare(`
    UPDATE folders
    SET name = ?, parent_id = ?, sort_order = ?, access_role = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(
    name !== undefined ? String(name).trim() : existing.name,
    parent_id !== undefined ? parent_id : existing.parent_id,
    sort_order !== undefined ? Number(sort_order) : existing.sort_order,
    access_role !== undefined ? access_role : existing.access_role,
    id
  );

  writeAudit(actor.full_name, actor.role, 'UPDATE', 'FOLDER', String(id), `Memperbarui folder "${name ?? existing.name}".`);
  res.json(db.prepare('SELECT * FROM folders WHERE id = ?').get(id));
});

app.delete('/api/folders/:id', (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT name FROM folders WHERE id = ?').get(id) as { name: string } | undefined;
  if (!existing) return res.status(404).json({ error: 'Folder tidak ditemukan.' });
  db.prepare('DELETE FROM folders WHERE id = ?').run(id);
  writeAudit(actor.full_name, actor.role, 'DELETE', 'FOLDER', String(id), `Menghapus folder "${existing.name}".`);
  res.json({ success: true });
});

app.get('/api/documents', (req, res) => {
  const u = getActor(req);
  const folderId = req.query.folderId ? Number(req.query.folderId) : null;
  const search = (req.query.search as string) || '';
  const fileType = (req.query.fileType as string) || 'all';
  const sortBy = (req.query.sortBy as string) || 'sort_order';
  const sortDir = (req.query.sortDir as string) === 'desc' ? 'DESC' : 'ASC';

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (folderId && !search) {
    conditions.push('folder_id = ?');
    params.push(folderId);
  } else if (folderId && search) {
    // When searching, search across all folders or current if specified
    conditions.push('folder_id = ?');
    params.push(folderId);
  }

  if (search.trim()) {
    conditions.push('(LOWER(name) LIKE ? OR LOWER(COALESCE(description, \'\')) LIKE ? OR LOWER(uploaded_by) LIKE ?)');
    const q = `%${search.trim().toLowerCase()}%`;
    params.push(q, q, q);
  }

  if (fileType !== 'all') {
    if (fileType === 'pdf') conditions.push("LOWER(file_ext) = 'pdf'");
    else if (fileType === 'word') conditions.push("LOWER(file_ext) IN ('doc', 'docx')");
    else if (fileType === 'excel') conditions.push("LOWER(file_ext) IN ('xls', 'xlsx', 'csv')");
    else if (fileType === 'ppt') conditions.push("LOWER(file_ext) IN ('ppt', 'pptx')");
    else if (fileType === 'image') conditions.push("LOWER(file_ext) IN ('jpg', 'jpeg', 'png', 'webp', 'gif')");
    else if (fileType === 'other') conditions.push("LOWER(file_ext) NOT IN ('pdf','doc','docx','xls','xlsx','csv','ppt','pptx','jpg','jpeg','png','webp','gif')");
  }

  let orderClause = `sort_order ${sortDir}, name ASC`;
  if (sortBy === 'name') orderClause = `name ${sortDir}`;
  if (sortBy === 'date') orderClause = `created_at ${sortDir}`;
  if (sortBy === 'size') orderClause = `size_bytes ${sortDir}`;

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const docs = db.prepare(`SELECT * FROM documents ${where} ORDER BY ${orderClause}`).all(...params) as Array<{ access_role: string }>;
  res.json(docs.filter((d) => canAccess(d.access_role, u.role)));
});

app.post('/api/documents/upload', uploadDocs.array('files', 20), (req, res) => {
  const actor = getActor(req);
  const folderId = Number(req.body.folder_id);
  const accessRole = (req.body.access_role as string) || 'ALL';
  const uploaderName = (req.body.uploaded_by as string) || actor.full_name;
  const description = (req.body.description as string) || '';
  const files = req.files as Express.Multer.File[] | undefined;

  if (!folderId || !files || files.length === 0) {
    return res.status(400).json({ error: 'Folder tujuan dan minimal 1 file wajib dipilih.' });
  }

  const maxOrderRow = db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM documents WHERE folder_id = ?').get(folderId) as { m: number };
  let nextOrder = maxOrderRow.m + 1;

  const insertStmt = db.prepare(`
    INSERT INTO documents (folder_id, name, original_name, mime_type, file_ext, size_bytes, storage_path, content_preview, uploaded_by, sort_order, access_role, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const createdDocs: unknown[] = [];
  for (const file of files) {
    const ext = path.extname(file.originalname).replace('.', '').toLowerCase() || 'bin';
    let textPreview: string | null = null;
    if (['txt', 'csv', 'md', 'json', 'log'].includes(ext)) {
      try {
        textPreview = fs.readFileSync(file.path, 'utf8').slice(0, 8000);
      } catch {
        textPreview = null;
      }
    }
    const info = insertStmt.run(
      folderId,
      file.originalname,
      file.originalname,
      file.mimetype,
      ext,
      file.size,
      `/uploads/docs/${path.basename(file.path)}`,
      textPreview,
      uploaderName,
      nextOrder++,
      accessRole,
      description || null
    );
    createdDocs.push(db.prepare('SELECT * FROM documents WHERE id = ?').get(info.lastInsertRowid));
  }

  writeAudit(actor.full_name, actor.role, 'CREATE', 'DOCUMENT', String(folderId), `Mengunggah ${files.length} dokumen ke folder #${folderId}.`);
  res.status(201).json(createdDocs);
});

app.get('/api/documents/:id/download', (req, res) => {
  const id = Number(req.params.id);
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(id) as
    | { name: string; storage_path: string; content_preview: string | null; mime_type: string }
    | undefined;
  if (!doc) return res.status(404).json({ error: 'Dokumen tidak ditemukan.' });

  if (doc.storage_path) {
    const filePath = path.resolve(process.cwd(), doc.storage_path.replace(/^\//, ''));
    if (fs.existsSync(filePath)) {
      return res.download(filePath, doc.name);
    }
  }
  // Seeded sample document fallback download
  const body = doc.content_preview || `Dokumen HSE SYSTEM: ${doc.name}`;
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.name)}.txt"`);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(body);
});

app.patch('/api/documents/:id', (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM documents WHERE id = ?').get(id) as
    | { id: number; name: string; folder_id: number; sort_order: number; access_role: string; description: string | null }
    | undefined;
  if (!existing) return res.status(404).json({ error: 'Dokumen tidak ditemukan.' });

  const { name, folder_id, sort_order, access_role, description } = req.body;
  db.prepare(`
    UPDATE documents
    SET name = ?, folder_id = ?, sort_order = ?, access_role = ?, description = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(
    name !== undefined ? String(name).trim() : existing.name,
    folder_id !== undefined ? Number(folder_id) : existing.folder_id,
    sort_order !== undefined ? Number(sort_order) : existing.sort_order,
    access_role !== undefined ? access_role : existing.access_role,
    description !== undefined ? description : existing.description,
    id
  );

  writeAudit(actor.full_name, actor.role, 'UPDATE', 'DOCUMENT', String(id), `Memperbarui dokumen "${name ?? existing.name}".`);
  res.json(db.prepare('SELECT * FROM documents WHERE id = ?').get(id));
});

app.post('/api/documents/:id/copy', (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const targetFolderId = Number(req.body.target_folder_id);
  const existing = db.prepare('SELECT * FROM documents WHERE id = ?').get(id) as
    | {
        name: string;
        original_name: string;
        mime_type: string;
        file_ext: string;
        size_bytes: number;
        storage_path: string;
        content_preview: string | null;
        access_role: string;
        description: string | null;
      }
    | undefined;
  if (!existing || !targetFolderId) {
    return res.status(400).json({ error: 'Dokumen atau folder tujuan tidak valid.' });
  }

  const maxOrder = (
    db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM documents WHERE folder_id = ?').get(targetFolderId) as { m: number }
  ).m;

  const newName = existing.name.includes('(Copy)') ? existing.name : `${existing.name} (Copy)`;
  const info = db
    .prepare(`
      INSERT INTO documents (folder_id, name, original_name, mime_type, file_ext, size_bytes, storage_path, content_preview, uploaded_by, sort_order, access_role, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      targetFolderId,
      newName,
      existing.original_name,
      existing.mime_type,
      existing.file_ext,
      existing.size_bytes,
      existing.storage_path,
      existing.content_preview,
      actor.full_name,
      maxOrder + 1,
      existing.access_role,
      existing.description
    );

  writeAudit(actor.full_name, actor.role, 'CREATE', 'DOCUMENT', String(info.lastInsertRowid), `Menyalin dokumen "${existing.name}" ke folder #${targetFolderId}.`);
  res.status(201).json(db.prepare('SELECT * FROM documents WHERE id = ?').get(info.lastInsertRowid));
});

app.post('/api/documents/bulk', (req, res) => {
  const actor = getActor(req);
  const { ids, action, target_folder_id } = req.body as { ids?: number[]; action?: 'delete' | 'move' | 'copy'; target_folder_id?: number };
  if (!ids || ids.length === 0 || !action) {
    return res.status(400).json({ error: 'Pilih minimal satu dokumen dan aksi.' });
  }

  const tx = db.transaction(() => {
    if (action === 'delete') {
      const del = db.prepare('DELETE FROM documents WHERE id = ?');
      for (const id of ids) del.run(id);
      writeAudit(actor.full_name, actor.role, 'DELETE', 'DOCUMENT', ids.join(','), `Menghapus ${ids.length} dokumen secara massal.`);
    } else if (action === 'move' && target_folder_id) {
      const mv = db.prepare("UPDATE documents SET folder_id = ?, updated_at = datetime('now') WHERE id = ?");
      for (const id of ids) mv.run(target_folder_id, id);
      writeAudit(actor.full_name, actor.role, 'UPDATE', 'DOCUMENT', ids.join(','), `Memindahkan ${ids.length} dokumen ke folder #${target_folder_id}.`);
    } else if (action === 'copy' && target_folder_id) {
      const getDoc = db.prepare('SELECT * FROM documents WHERE id = ?');
      const ins = db.prepare(`
        INSERT INTO documents (folder_id, name, original_name, mime_type, file_ext, size_bytes, storage_path, content_preview, uploaded_by, sort_order, access_role, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const id of ids) {
        const d = getDoc.get(id) as Record<string, unknown> | undefined;
        if (d) {
          ins.run(
            target_folder_id,
            `${d.name} (Copy)`,
            d.original_name,
            d.mime_type,
            d.file_ext,
            d.size_bytes,
            d.storage_path,
            d.content_preview,
            actor.full_name,
            d.sort_order,
            d.access_role,
            d.description
          );
        }
      }
      writeAudit(actor.full_name, actor.role, 'CREATE', 'DOCUMENT', ids.join(','), `Menyalin ${ids.length} dokumen ke folder #${target_folder_id}.`);
    }
  });
  tx();
  res.json({ success: true });
});

app.delete('/api/documents/:id', (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const doc = db.prepare('SELECT name FROM documents WHERE id = ?').get(id) as { name: string } | undefined;
  if (!doc) return res.status(404).json({ error: 'Dokumen tidak ditemukan.' });
  db.prepare('DELETE FROM documents WHERE id = ?').run(id);
  writeAudit(actor.full_name, actor.role, 'DELETE', 'DOCUMENT', String(id), `Menghapus dokumen "${doc.name}".`);
  res.json({ success: true });
});

// ================= EQUIPMENT & CATEGORIES =================
app.get('/api/categories', (_req, res) => {
  res.json(db.prepare('SELECT * FROM equipment_categories ORDER BY id ASC').all());
});

app.get('/api/equipment', (req, res) => {
  const search = (req.query.search as string) || '';
  const categoryId = req.query.categoryId ? Number(req.query.categoryId) : null;
  const status = (req.query.status as string) || 'all';

  const conds: string[] = [];
  const params: unknown[] = [];

  if (search.trim()) {
    const q = `%${search.trim().toLowerCase()}%`;
    conds.push('(LOWER(e.asset_number) LIKE ? OR LOWER(e.name) LIKE ? OR LOWER(e.location) LIKE ? OR LOWER(e.qr_code_value) LIKE ?)');
    params.push(q, q, q, q);
  }
  if (categoryId) {
    conds.push('e.category_id = ?');
    params.push(categoryId);
  }
  if (status !== 'all') {
    conds.push('e.status = ?');
    params.push(status);
  }

  const where = conds.length > 0 ? `WHERE ${conds.join(' AND ')}` : '';
  const rows = db
    .prepare(`
      SELECT e.*, c.name as category_name, c.code_prefix as category_prefix, c.default_image_key
      FROM equipment e
      JOIN equipment_categories c ON c.id = e.category_id
      ${where}
      ORDER BY c.id ASC, e.asset_number ASC
    `)
    .all(...params) as Array<Record<string, unknown>>;

  const latestStmt = db.prepare(`
    SELECT * FROM inspections WHERE equipment_id = ? ORDER BY inspected_at DESC, id DESC LIMIT 1
  `);

  const enriched = rows.map((eq) => {
    const latest = latestStmt.get(eq.id) as { overall_status?: string } | undefined;
    return {
      ...eq,
      latest_inspection: latest || null,
      latest_status: latest?.overall_status || 'UNINSPECTED',
    };
  });

  res.json(enriched);
});

app.get('/api/equipment/lookup', (req, res) => {
  const rawCode = String(req.query.code || '').trim();
  if (!rawCode) {
    return res.status(400).json({ error: 'Kode QR atau Nomor Asset kosong.' });
  }

  // Support direct QR value, asset_number, or URL query like ?eq=WF01
  let normalized = rawCode;
  try {
    if (rawCode.startsWith('http://') || rawCode.startsWith('https://')) {
      const parsed = new URL(rawCode);
      normalized = parsed.searchParams.get('eq') || parsed.searchParams.get('qr') || rawCode;
    }
  } catch {
    // ignore URL parse error
  }

  const eq = db
    .prepare(`
      SELECT e.*, c.name as category_name, c.code_prefix as category_prefix, c.default_image_key
      FROM equipment e
      JOIN equipment_categories c ON c.id = e.category_id
      WHERE LOWER(e.qr_code_value) = LOWER(?) OR LOWER(e.asset_number) = LOWER(?)
      LIMIT 1
    `)
    .get(normalized, normalized) as Record<string, unknown> | undefined;

  if (!eq) {
    return res.status(404).json({ error: 'Equipment tidak ditemukan dalam database.' });
  }

  const latest = db
    .prepare('SELECT * FROM inspections WHERE equipment_id = ? ORDER BY inspected_at DESC, id DESC LIMIT 1')
    .get(eq.id) as { overall_status?: string } | undefined;

  res.json({
    ...eq,
    latest_inspection: latest || null,
    latest_status: latest?.overall_status || 'UNINSPECTED',
  });
});

app.get('/api/equipment/:id', (req, res) => {
  const id = Number(req.params.id);
  const eq = db
    .prepare(`
      SELECT e.*, c.name as category_name, c.code_prefix as category_prefix, c.default_image_key
      FROM equipment e
      JOIN equipment_categories c ON c.id = e.category_id
      WHERE e.id = ?
    `)
    .get(id) as Record<string, unknown> | undefined;

  if (!eq) return res.status(404).json({ error: 'Equipment tidak ditemukan dalam database.' });

  const history = db
    .prepare(`
      SELECT i.*, e.asset_number, e.name as equipment_name, e.location, c.name as category_name
      FROM inspections i
      JOIN equipment e ON e.id = i.equipment_id
      JOIN equipment_categories c ON c.id = e.category_id
      WHERE i.equipment_id = ?
      ORDER BY i.inspected_at DESC, i.id DESC
    `)
    .all(id);

  const items = db
    .prepare('SELECT * FROM inspection_items WHERE category_id = ? AND is_active = 1 ORDER BY sort_order ASC, id ASC')
    .all(eq.category_id);

  res.json({
    equipment: {
      ...eq,
      latest_inspection: history[0] || null,
      latest_status: (history[0] as { overall_status?: string } | undefined)?.overall_status || 'UNINSPECTED',
    },
    history,
    checklist_items: items,
  });
});

app.post('/api/equipment', requireRole(['ADMIN']), uploadPhoto.single('photo'), (req, res) => {
  const actor = getActor(req);
  const { asset_number, name, category_id, location, registration_date, notes, qr_code_value } = req.body;
  if (!asset_number || !name || !category_id || !location) {
    return res.status(400).json({ error: 'Nomor Asset, Nama Equipment, Kategori, dan Lokasi wajib diisi.' });
  }

  const cleanAsset = String(asset_number).trim().toUpperCase();
  const cleanQr = qr_code_value && String(qr_code_value).trim() ? String(qr_code_value).trim() : `HSE-EQ-${cleanAsset}`;

  const dup = db
    .prepare('SELECT id FROM equipment WHERE LOWER(asset_number) = LOWER(?) OR LOWER(qr_code_value) = LOWER(?)')
    .get(cleanAsset, cleanQr);
  if (dup) {
    return res.status(409).json({ error: 'Nomor Asset atau Kode QR sudah terdaftar pada equipment lain.' });
  }

  const photoUrl = req.file ? `/uploads/photos/${path.basename(req.file.path)}` : null;
  const regDate = registration_date || new Date().toISOString().slice(0, 10);

  const info = db
    .prepare(`
      INSERT INTO equipment (asset_number, name, category_id, location, photo_url, qr_code_value, registration_date, status, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
    `)
    .run(cleanAsset, String(name).trim(), Number(category_id), String(location).trim(), photoUrl, cleanQr, regDate, notes || null);

  writeAudit(actor.full_name, actor.role, 'CREATE', 'EQUIPMENT', cleanAsset, `Mendaftarkan equipment baru ${name} (${cleanAsset}) di ${location}.`);
  const created = db
    .prepare(`
      SELECT e.*, c.name as category_name, c.code_prefix as category_prefix, c.default_image_key
      FROM equipment e JOIN equipment_categories c ON c.id = e.category_id WHERE e.id = ?
    `)
    .get(info.lastInsertRowid);
  res.status(201).json(created);
});

app.patch('/api/equipment/:id', requireRole(['ADMIN']), uploadPhoto.single('photo'), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM equipment WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: 'Equipment tidak ditemukan.' });

  const { asset_number, name, category_id, location, qr_code_value, status, notes } = req.body;
  const nextAsset = asset_number !== undefined ? String(asset_number).trim().toUpperCase() : String(existing.asset_number);
  const nextQr = qr_code_value !== undefined ? String(qr_code_value).trim() : String(existing.qr_code_value);

  const dup = db
    .prepare('SELECT id FROM equipment WHERE id != ? AND (LOWER(asset_number) = LOWER(?) OR LOWER(qr_code_value) = LOWER(?))')
    .get(id, nextAsset, nextQr);
  if (dup) {
    return res.status(409).json({ error: 'Nomor Asset atau Kode QR bentrok dengan equipment lain.' });
  }

  const photoUrl = req.file ? `/uploads/photos/${path.basename(req.file.path)}` : (existing.photo_url as string | null);

  db.prepare(`
    UPDATE equipment
    SET asset_number = ?, name = ?, category_id = ?, location = ?, photo_url = ?, qr_code_value = ?, status = ?, notes = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(
    nextAsset,
    name ?? existing.name,
    category_id ? Number(category_id) : existing.category_id,
    location ?? existing.location,
    photoUrl,
    nextQr,
    status ?? existing.status,
    notes !== undefined ? notes : existing.notes,
    id
  );

  writeAudit(actor.full_name, actor.role, 'UPDATE', 'EQUIPMENT', nextAsset, `Memperbarui equipment ${nextAsset} (QR: ${nextQr}).`);
  const updated = db
    .prepare(`
      SELECT e.*, c.name as category_name, c.code_prefix as category_prefix, c.default_image_key
      FROM equipment e JOIN equipment_categories c ON c.id = e.category_id WHERE e.id = ?
    `)
    .get(id);
  res.json(updated);
});

app.delete('/api/equipment/:id', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT asset_number FROM equipment WHERE id = ?').get(id) as { asset_number: string } | undefined;
  if (!existing) return res.status(404).json({ error: 'Equipment tidak ditemukan.' });
  db.prepare('DELETE FROM equipment WHERE id = ?').run(id);
  writeAudit(actor.full_name, actor.role, 'DELETE', 'EQUIPMENT', existing.asset_number, `Menghapus equipment ${existing.asset_number}.`);
  res.json({ success: true });
});

// ================= INSPECTION ITEMS & QUESTIONS (PENGATURAN INSPEKSI) =================
app.get('/api/inspection-items', (req, res) => {
  const categoryId = req.query.categoryId ? Number(req.query.categoryId) : null;
  const includeInactive = req.query.includeInactive === 'true';

  const conds: string[] = [];
  const params: unknown[] = [];
  if (categoryId) {
    conds.push('ii.category_id = ?');
    params.push(categoryId);
  }
  if (!includeInactive) {
    conds.push('ii.is_active = 1');
  }
  const where = conds.length > 0 ? `WHERE ${conds.join(' AND ')}` : '';
  const items = db
    .prepare(`
      SELECT ii.*, c.name as category_name
      FROM inspection_items ii
      JOIN equipment_categories c ON c.id = ii.category_id
      ${where}
      ORDER BY ii.category_id ASC, ii.sort_order ASC, ii.id ASC
    `)
    .all(...params);
  res.json(items);
});

app.post('/api/inspection-items', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const { category_id, item_name, question_text, answer_type, options_json, is_required } = req.body;
  if (!category_id || !item_name || !question_text) {
    return res.status(400).json({ error: 'Kategori, nama item, dan pertanyaan wajib diisi.' });
  }
  const maxOrder = (
    db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM inspection_items WHERE category_id = ?').get(Number(category_id)) as { m: number }
  ).m;

  const optsStr = typeof options_json === 'string' ? options_json : JSON.stringify(options_json || []);
  const info = db
    .prepare(`
      INSERT INTO inspection_items (category_id, item_name, question_text, answer_type, options_json, is_required, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `)
    .run(
      Number(category_id),
      String(item_name).trim(),
      String(question_text).trim(),
      answer_type || 'radio',
      optsStr,
      is_required === false ? 0 : 1,
      maxOrder + 1
    );

  writeAudit(actor.full_name, actor.role, 'CREATE', 'CHECKLIST_ITEM', String(info.lastInsertRowid), `Menambah item ceklis "${item_name}" untuk kategori #${category_id}.`);
  const created = db
    .prepare('SELECT ii.*, c.name as category_name FROM inspection_items ii JOIN equipment_categories c ON c.id = ii.category_id WHERE ii.id = ?')
    .get(info.lastInsertRowid);
  res.status(201).json(created);
});

app.patch('/api/inspection-items/:id', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM inspection_items WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: 'Item ceklis tidak ditemukan.' });

  const { category_id, item_name, question_text, answer_type, options_json, is_required, sort_order, is_active } = req.body;
  const nextOpts =
    options_json !== undefined
      ? typeof options_json === 'string'
        ? options_json
        : JSON.stringify(options_json)
      : existing.options_json;

  db.prepare(`
    UPDATE inspection_items
    SET category_id = ?, item_name = ?, question_text = ?, answer_type = ?, options_json = ?, is_required = ?, sort_order = ?, is_active = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(
    category_id !== undefined ? Number(category_id) : existing.category_id,
    item_name !== undefined ? String(item_name).trim() : existing.item_name,
    question_text !== undefined ? String(question_text).trim() : existing.question_text,
    answer_type !== undefined ? answer_type : existing.answer_type,
    nextOpts,
    is_required !== undefined ? (is_required ? 1 : 0) : existing.is_required,
    sort_order !== undefined ? Number(sort_order) : existing.sort_order,
    is_active !== undefined ? (is_active ? 1 : 0) : existing.is_active,
    id
  );

  writeAudit(actor.full_name, actor.role, 'UPDATE', 'CHECKLIST_ITEM', String(id), `Mengubah item/pertanyaan "${item_name ?? existing.item_name}".`);
  const updated = db
    .prepare('SELECT ii.*, c.name as category_name FROM inspection_items ii JOIN equipment_categories c ON c.id = ii.category_id WHERE ii.id = ?')
    .get(id);
  res.json(updated);
});

app.delete('/api/inspection-items/:id', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT item_name FROM inspection_items WHERE id = ?').get(id) as { item_name: string } | undefined;
  if (!existing) return res.status(404).json({ error: 'Item ceklis tidak ditemukan.' });
  // Note: Historical inspections remain completely untouched because they store a JSON snapshot
  db.prepare('DELETE FROM inspection_items WHERE id = ?').run(id);
  writeAudit(actor.full_name, actor.role, 'DELETE', 'CHECKLIST_ITEM', String(id), `Menghapus item ceklis "${existing.item_name}" (histori lama tetap tersimpan).`);
  res.json({ success: true });
});

// ================= INSPECTIONS & EXPORT =================
function createInspectionRecord(payload: {
  equipment_id: number;
  inspected_at?: string;
  inspector_name: string;
  inspector_user_id: number | null;
  answers: Array<{ item_id: number; item_name: string; question_text: string; answer_type: string; answer_value: string | string[]; item_status: 'NORMAL' | 'ATTENTION' | 'ABNORMAL' }>;
  notes?: string;
  finding_photo_url?: string | null;
  synced_from_offline?: number;
}) {
  const eq = db.prepare('SELECT * FROM equipment WHERE id = ?').get(payload.equipment_id) as
    | { id: number; asset_number: string; name: string }
    | undefined;
  if (!eq) throw new Error('Equipment tidak ditemukan dalam database.');

  let overallStatus: 'NORMAL' | 'ATTENTION' | 'ABNORMAL' = 'NORMAL';
  for (const ans of payload.answers) {
    if (ans.item_status === 'ABNORMAL') {
      overallStatus = 'ABNORMAL';
      break;
    }
    if (ans.item_status === 'ATTENTION') {
      overallStatus = 'ATTENTION';
    }
  }

  const timestamp = payload.inspected_at || new Date().toISOString().replace('T', ' ').slice(0, 19);
  const info = db
    .prepare(`
      INSERT INTO inspections (equipment_id, inspected_at, inspector_name, inspector_user_id, answers_json, notes, finding_photo_url, overall_status, synced_from_offline)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      payload.equipment_id,
      timestamp,
      payload.inspector_name.trim() || 'Inspector Lapangan',
      payload.inspector_user_id,
      JSON.stringify(payload.answers),
      payload.notes || null,
      payload.finding_photo_url || null,
      overallStatus,
      payload.synced_from_offline ? 1 : 0
    );

  const inspId = Number(info.lastInsertRowid);

  if (overallStatus === 'ABNORMAL' || overallStatus === 'ATTENTION') {
    db.prepare(`
      INSERT INTO notifications (type, title, message, equipment_id, inspection_id, is_read)
      VALUES (?, ?, ?, ?, ?, 0)
    `).run(
      overallStatus === 'ABNORMAL' ? 'ABNORMAL_FINDING' : 'ATTENTION',
      `${overallStatus === 'ABNORMAL' ? 'Temuan Abnormal' : 'Perlu Perhatian'}: ${eq.name} (${eq.asset_number})`,
      payload.notes || `Pemeriksaan oleh ${payload.inspector_name} menghasilkan status ${overallStatus}.`,
      eq.id,
      inspId
    );
  }

  writeAudit(
    payload.inspector_name,
    payload.inspector_user_id ? 'INSPECTOR' : 'FIELD_GUEST',
    'INSPECT',
    'EQUIPMENT',
    eq.asset_number,
    `Inspeksi ${eq.asset_number} oleh ${payload.inspector_name} — Status: ${overallStatus}.`
  );

  return db
    .prepare(`
      SELECT i.*, e.asset_number, e.name as equipment_name, e.location, c.name as category_name
      FROM inspections i
      JOIN equipment e ON e.id = i.equipment_id
      JOIN equipment_categories c ON c.id = e.category_id
      WHERE i.id = ?
    `)
    .get(inspId);
}

app.post('/api/inspections', uploadPhoto.single('finding_photo'), (req, res) => {
  const actor = getActor(req);
  // VIEWER role cannot submit inspections if logged in strictly as VIEWER
  if (actor.isAuthenticated && actor.role === 'VIEWER') {
    return res.status(403).json({ error: 'Akun VIEWER hanya memiliki akses lihat hasil (read-only).' });
  }

  try {
    const equipmentId = Number(req.body.equipment_id);
    const inspectorName = String(req.body.inspector_name || (actor.isAuthenticated ? actor.full_name : 'Inspector Lapangan'));
    const notes = req.body.notes ? String(req.body.notes) : '';
    const inspectedAt = req.body.inspected_at ? String(req.body.inspected_at) : undefined;
    const answers = typeof req.body.answers_json === 'string' ? JSON.parse(req.body.answers_json) : req.body.answers || [];
    const findingPhotoUrl = req.file ? `/uploads/photos/${path.basename(req.file.path)}` : req.body.finding_photo_data_url || null;

    const record = createInspectionRecord({
      equipment_id: equipmentId,
      inspected_at: inspectedAt,
      inspector_name: inspectorName,
      inspector_user_id: actor.id,
      answers,
      notes,
      finding_photo_url: findingPhotoUrl,
      synced_from_offline: req.body.synced_from_offline ? 1 : 0,
    });
    res.status(201).json(record);
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Gagal menyimpan inspeksi.' });
  }
});

app.post('/api/inspections/sync', (req, res) => {
  const actor = getActor(req);
  const items = req.body.items as Array<{
    equipment_id: number;
    inspected_at: string;
    inspector_name: string;
    answers: Array<{ item_id: number; item_name: string; question_text: string; answer_type: string; answer_value: string | string[]; item_status: 'NORMAL' | 'ATTENTION' | 'ABNORMAL' }>;
    notes?: string;
    finding_photo_data_url?: string | null;
  }>;

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Tidak ada data antrean offline untuk disinkronkan.' });
  }

  const synced: unknown[] = [];
  const tx = db.transaction(() => {
    for (const item of items) {
      synced.push(
        createInspectionRecord({
          equipment_id: item.equipment_id,
          inspected_at: item.inspected_at,
          inspector_name: item.inspector_name,
          inspector_user_id: actor.id,
          answers: item.answers,
          notes: item.notes,
          finding_photo_url: item.finding_photo_data_url || null,
          synced_from_offline: 1,
        })
      );
    }
  });
  tx();
  res.json({ synced_count: synced.length, records: synced });
});

app.get('/api/inspections/export', (req, res) => {
  const startDate = (req.query.startDate as string) || '';
  const endDate = (req.query.endDate as string) || '';
  const categoryIdsStr = (req.query.categoryIds as string) || '';
  const location = (req.query.location as string) || '';
  const assetNumber = (req.query.assetNumber as string) || '';
  const status = (req.query.status as string) || 'all';
  const inspectorName = (req.query.inspectorName as string) || '';

  const conds: string[] = [];
  const params: unknown[] = [];

  if (startDate) {
    conds.push('substr(i.inspected_at, 1, 10) >= ?');
    params.push(startDate);
  }
  if (endDate) {
    conds.push('substr(i.inspected_at, 1, 10) <= ?');
    params.push(endDate);
  }
  if (categoryIdsStr && categoryIdsStr !== 'all') {
    const ids = categoryIdsStr
      .split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => !Number.isNaN(n) && n > 0);
    if (ids.length > 0) {
      conds.push(`e.category_id IN (${ids.map(() => '?').join(',')})`);
      params.push(...ids);
    }
  }
  if (location.trim()) {
    conds.push('LOWER(e.location) LIKE ?');
    params.push(`%${location.trim().toLowerCase()}%`);
  }
  if (assetNumber.trim()) {
    conds.push('LOWER(e.asset_number) LIKE ?');
    params.push(`%${assetNumber.trim().toLowerCase()}%`);
  }
  if (status && status !== 'all') {
    conds.push('i.overall_status = ?');
    params.push(status);
  }
  if (inspectorName.trim()) {
    conds.push('LOWER(i.inspector_name) LIKE ?');
    params.push(`%${inspectorName.trim().toLowerCase()}%`);
  }

  const where = conds.length > 0 ? `WHERE ${conds.join(' AND ')}` : '';
  const rows = db
    .prepare(`
      SELECT i.*, e.asset_number, e.name as equipment_name, e.location, c.id as category_id, c.name as category_name
      FROM inspections i
      JOIN equipment e ON e.id = i.equipment_id
      JOIN equipment_categories c ON c.id = e.category_id
      ${where}
      ORDER BY i.inspected_at DESC, i.id DESC
    `)
    .all(...params);

  res.json(rows);
});

// ================= BACKUP & RESTORE =================
app.get('/api/backup/export', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const payload = {
    exported_at: new Date().toISOString(),
    app: 'HSE SYSTEM',
    tables: {
      folders: db.prepare('SELECT * FROM folders').all(),
      documents: db.prepare('SELECT * FROM documents').all(),
      equipment_categories: db.prepare('SELECT * FROM equipment_categories').all(),
      equipment: db.prepare('SELECT * FROM equipment').all(),
      inspection_items: db.prepare('SELECT * FROM inspection_items').all(),
      inspections: db.prepare('SELECT * FROM inspections').all(),
      notifications: db.prepare('SELECT * FROM notifications').all(),
    },
  };
  writeAudit(actor.full_name, actor.role, 'BACKUP', 'DATABASE', 'ALL', 'Mengunduh backup lengkap database HSE SYSTEM.');
  res.setHeader('Content-Disposition', `attachment; filename="hse-system-backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(payload);
});

app.post('/api/backup/restore', requireRole(['ADMIN']), (req, res) => {
  const actor = getActor(req);
  const backup = req.body?.tables;
  if (!backup || !Array.isArray(backup.equipment_categories) || !Array.isArray(backup.equipment)) {
    return res.status(400).json({ error: 'Format file backup tidak valid.' });
  }

  try {
    const tx = db.transaction(() => {
      db.pragma('foreign_keys = OFF');
      db.prepare('DELETE FROM notifications').run();
      db.prepare('DELETE FROM inspections').run();
      db.prepare('DELETE FROM inspection_items').run();
      db.prepare('DELETE FROM equipment').run();
      db.prepare('DELETE FROM equipment_categories').run();
      db.prepare('DELETE FROM documents').run();
      db.prepare('DELETE FROM folders').run();

      const insertRow = (table: string, rows: Record<string, unknown>[]) => {
        if (!rows || rows.length === 0) return;
        const cols = Object.keys(rows[0]);
        const stmt = db.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`);
        for (const r of rows) {
          stmt.run(...cols.map((c) => r[c] ?? null));
        }
      };

      insertRow('folders', backup.folders || []);
      insertRow('documents', backup.documents || []);
      insertRow('equipment_categories', backup.equipment_categories || []);
      insertRow('equipment', backup.equipment || []);
      insertRow('inspection_items', backup.inspection_items || []);
      insertRow('inspections', backup.inspections || []);
      insertRow('notifications', backup.notifications || []);
      db.pragma('foreign_keys = ON');
    });
    tx();
    writeAudit(actor.full_name, actor.role, 'RESTORE', 'DATABASE', 'ALL', 'Melakukan pemulihan database dari file backup JSON.');
    res.json({ success: true });
  } catch (err: unknown) {
    db.pragma('foreign_keys = ON');
    res.status(500).json({ error: err instanceof Error ? err.message : 'Gagal memulihkan backup.' });
  }
});

// ================= EXPORT PROJECT SOURCE CODE ZIP =================
app.get('/api/system/download-source', async (_req, res) => {
  try {
    const zip = new JSZip();
    const rootDir = process.cwd();
    const excludedDirs = new Set(['node_modules', 'dist', 'data', 'uploads', '.git', 'build', 'coverage']);
    const excludedFiles = new Set(['.env', '.env.local', '.env.production', '.DS_Store']);

    const addDirToZip = (dirPath: string, relBase: string) => {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (excludedDirs.has(entry.name)) continue;
          addDirToZip(path.join(dirPath, entry.name), relBase ? `${relBase}/${entry.name}` : entry.name);
        } else if (entry.isFile()) {
          if (excludedFiles.has(entry.name) || entry.name.startsWith('.env.')) continue;
          const fullPath = path.join(dirPath, entry.name);
          const zipPath = relBase ? `${relBase}/${entry.name}` : entry.name;
          zip.file(zipPath, fs.readFileSync(fullPath));
        }
      }
    };

    addDirToZip(rootDir, '');
    const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="hse-system-source.zip"');
    res.send(buffer);
  } catch (err: unknown) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Gagal membuat file ZIP.' });
  }
});

// ================= VITE / STATIC FRONTEND =================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`HSE SYSTEM server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
