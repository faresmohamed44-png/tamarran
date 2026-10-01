const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const seed = require('./seed');

const PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || (PROD ? null : 'dev-only-secret');

if (!DB_URL) { console.error('ناقص متغير DATABASE_URL'); process.exit(1); }
if (!JWT_SECRET) { console.error('ناقص متغير JWT_SECRET'); process.exit(1); }

const pool = new Pool({
  connectionString: DB_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DB_URL) ? false : { rejectUnauthorized: false }
});

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- أدوات ---------- */
const h = fn => (req, res, next) => fn(req, res, next).catch(next);
const fail = (res, code, msg) => res.status(code).json({ error: msg });
const clean = s => String(s ?? '').trim();

function setSession(res, user) {
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 7 * 24 * 3600 * 1000 });
}
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

const auth = h(async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return fail(res, 401, 'سجّل دخولك الأول');
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch (e) { return fail(res, 401, 'انتهت الجلسة، سجّل دخولك تاني'); }
  const { rows } = await pool.query('select * from users where id=$1', [payload.id]);
  if (!rows[0]) return fail(res, 401, 'الحساب غير موجود');
  req.user = rows[0];
  next();
});
const teacherOnly = (req, res, next) => req.user.role === 'teacher' ? next() : fail(res, 403, 'الصفحة دي للمدرس فقط');

/* محاولات الدخول: حد بسيط في الذاكرة ضد التخمين */
const tries = new Map();
function tooMany(key) {
  const now = Date.now();
  const arr = (tries.get(key) || []).filter(t => now - t < 15 * 60 * 1000);
  tries.set(key, arr);
  return arr.length >= 10;
}
const noteTry = key => tries.set(key, [...(tries.get(key) || []), Date.now()]);

/* ---------- حسابات ---------- */
app.post('/api/register', h(async (req, res) => {
  const name = clean(req.body.name), email = clean(req.body.email).toLowerCase(), password = String(req.body.password || '');
  if (name.length < 2) return fail(res, 400, 'اكتب اسمك');
  if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, 'البريد الإلكتروني غير صحيح');
  if (password.length < 6) return fail(res, 400, 'كلمة المرور لازم تكون 6 حروف على الأقل');
  const exists = await pool.query('select 1 from users where email=$1', [email]);
  if (exists.rowCount) return fail(res, 409, 'البريد ده مسجّل قبل كده');
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    "insert into users(name,email,password_hash,role) values($1,$2,$3,'student') returning *", [name, email, hash]);
  setSession(res, rows[0]);
  res.json({ user: publicUser(rows[0]) });
}));

app.post('/api/login', h(async (req, res) => {
  const email = clean(req.body.email).toLowerCase(), password = String(req.body.password || '');
  const key = req.ip + '|' + email;
  if (tooMany(key)) return fail(res, 429, 'محاولات كتير. استنى 15 دقيقة وجرّب تاني');
  const { rows } = await pool.query('select * from users where email=$1', [email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    noteTry(key);
    return fail(res, 401, 'البريد أو كلمة المرور غلط');
  }
  setSession(res, u);
  res.json({ user: publicUser(u) });
}));

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

/* ---------- الطالب: الوحدات والامتحان ---------- */
app.get('/api/units', auth, h(async (req, res) => {
  const { rows } = await pool.query(`
    select u.id u_id, u.title u_title, u.description u_desc,
           m.id m_id, m.title m_title, m.minutes,
           (select count(*)::int from questions q where q.model_id = m.id) cnt,
           (select row_to_json(b) from (
              select a.score, a.total from attempts a
              where a.user_id = $1 and a.model_id = m.id
              order by a.score::float / a.total desc, a.created_at desc limit 1) b) best
    from units u left join models m on m.unit_id = u.id
    order by u.id, m.id`, [req.user.id]);
  const map = new Map();
  for (const r of rows) {
    if (!map.has(r.u_id)) map.set(r.u_id, { id: r.u_id, title: r.u_title, description: r.u_desc, models: [] });
    if (r.m_id) map.get(r.u_id).models.push({ id: r.m_id, title: r.m_title, minutes: r.minutes, count: r.cnt, best: r.best });
  }
  res.json({ units: [...map.values()] });
}));

function shuffle(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

// الأسئلة بتتبعت من غير الإجابة الصحيحة
app.get('/api/models/:id/exam', auth, h(async (req, res) => {
  const id = +req.params.id;
  const m = await pool.query('select m.id, m.title, m.minutes, m.unit_id, u.title unit_title from models m join units u on u.id = m.unit_id where m.id=$1', [id]);
  if (!m.rows[0]) return fail(res, 404, 'النموذج غير موجود');
  const qs = await pool.query('select id, text, options from questions where model_id=$1 order by id', [id]);
  if (!qs.rowCount) return fail(res, 404, 'النموذج ده لسه مفيهوش أسئلة');
  const questions = shuffle(qs.rows).map(q => ({
    id: q.id, text: q.text,
    options: shuffle(q.options.map((t, i) => ({ i, t })))
  }));
  res.json({ model: m.rows[0], questions });
}));

// التصحيح على السيرفر
app.post('/api/models/:id/submit', auth, h(async (req, res) => {
  const id = +req.params.id;
  const qs = (await pool.query('select * from questions where model_id=$1 order by id', [id])).rows;
  if (!qs.length) return fail(res, 404, 'النموذج غير موجود');
  const given = new Map((Array.isArray(req.body.answers) ? req.body.answers : []).map(a => [+a.qid, a.choice]));
  let score = 0; const stored = [], review = [];
  for (const q of qs) {
    const c = given.get(q.id);
    const has = Number.isInteger(c) && c >= 0 && c < q.options.length;
    const ok = has && c === q.correct;
    if (ok) score++;
    stored.push({ qid: q.id, choice: has ? c : null, ok });
    review.push({ text: q.text, chosen: has ? q.options[c] : null, correct: q.options[q.correct], ok, explanation: q.explanation });
  }
  await pool.query('insert into attempts(user_id, model_id, score, total, answers) values($1,$2,$3,$4,$5)',
    [req.user.id, id, score, qs.length, JSON.stringify(stored)]);
  res.json({ score, total: qs.length, review });
}));

/* ---------- المدرس ---------- */
const admin = express.Router();
admin.use(auth, teacherOnly);

admin.get('/overview', h(async (req, res) => {
  const [students, attempts, models, hard, recent] = await Promise.all([
    pool.query("select count(*)::int n from users where role='student'"),
    pool.query('select count(*)::int n from attempts'),
    pool.query(`select m.id, m.title, u.title unit_title, count(a.id)::int attempts,
                       round(avg(a.score::numeric / a.total * 100))::int avg
                from models m join units u on u.id = m.unit_id left join attempts a on a.model_id = m.id
                group by m.id, u.title, u.id order by u.id, m.id`),
    pool.query(`select q.id, q.text, s.n, s.right_n from (
                  select (x->>'qid')::int qid, count(*)::int n,
                         sum(case when (x->>'ok')::boolean then 1 else 0 end)::int right_n
                  from attempts, jsonb_array_elements(answers) x group by 1) s
                join questions q on q.id = s.qid
                order by s.right_n::float / s.n asc, s.n desc limit 5`),
    pool.query(`select u.name, m.title model_title, a.score, a.total, a.created_at
                from attempts a join users u on u.id = a.user_id join models m on m.id = a.model_id
                order by a.created_at desc limit 10`)
  ]);
  res.json({ students: students.rows[0].n, attempts: attempts.rows[0].n, models: models.rows, hardest: hard.rows, recent: recent.rows });
}));

// وحدات
admin.post('/units', h(async (req, res) => {
  const title = clean(req.body.title);
  if (!title) return fail(res, 400, 'اكتب اسم الوحدة');
  const { rows } = await pool.query('insert into units(title, description) values($1,$2) returning *', [title, clean(req.body.description)]);
  res.json(rows[0]);
}));
admin.put('/units/:id', h(async (req, res) => {
  const title = clean(req.body.title);
  if (!title) return fail(res, 400, 'اكتب اسم الوحدة');
  const { rows } = await pool.query('update units set title=$1, description=$2 where id=$3 returning *', [title, clean(req.body.description), +req.params.id]);
  rows[0] ? res.json(rows[0]) : fail(res, 404, 'الوحدة غير موجودة');
}));
admin.delete('/units/:id', h(async (req, res) => {
  await pool.query('delete from units where id=$1', [+req.params.id]);
  res.json({ ok: true });
}));

// نماذج
admin.post('/models', h(async (req, res) => {
  const title = clean(req.body.title), minutes = +req.body.minutes;
  if (!title) return fail(res, 400, 'اكتب اسم النموذج');
  if (!(minutes >= 1 && minutes <= 300)) return fail(res, 400, 'المدة لازم تكون بين 1 و300 دقيقة');
  const { rows } = await pool.query('insert into models(unit_id, title, minutes) values($1,$2,$3) returning *', [+req.body.unit_id, title, Math.round(minutes)]);
  res.json(rows[0]);
}));
admin.put('/models/:id', h(async (req, res) => {
  const title = clean(req.body.title), minutes = +req.body.minutes;
  if (!title) return fail(res, 400, 'اكتب اسم النموذج');
  if (!(minutes >= 1 && minutes <= 300)) return fail(res, 400, 'المدة لازم تكون بين 1 و300 دقيقة');
  const { rows } = await pool.query('update models set title=$1, minutes=$2 where id=$3 returning *', [title, Math.round(minutes), +req.params.id]);
  rows[0] ? res.json(rows[0]) : fail(res, 404, 'النموذج غير موجود');
}));
admin.delete('/models/:id', h(async (req, res) => {
  await pool.query('delete from models where id=$1', [+req.params.id]);
  res.json({ ok: true });
}));

// أسئلة
function parseQuestion(b) {
  const text = clean(b.text), explanation = clean(b.explanation);
  const options = Array.isArray(b.options) ? b.options.map(clean) : [];
  const correct = Number(b.correct);
  if (!text) return { error: 'اكتب نص السؤال' };
  if (options.length < 2 || options.length > 6 || options.some(o => !o)) return { error: 'لازم من 2 إلى 6 اختيارات ومن غير خانات فاضية' };
  if (!Number.isInteger(correct) || correct < 0 || correct >= options.length) return { error: 'حدد الإجابة الصحيحة' };
  return { text, options, correct, explanation };
}
admin.get('/models/:id/questions', h(async (req, res) => {
  const id = +req.params.id;
  const m = await pool.query('select m.id, m.title, m.unit_id, u.title unit_title from models m join units u on u.id=m.unit_id where m.id=$1', [id]);
  if (!m.rows[0]) return fail(res, 404, 'النموذج غير موجود');
  const q = await pool.query('select id, text, options, correct, explanation from questions where model_id=$1 order by id', [id]);
  res.json({ model: m.rows[0], questions: q.rows });
}));
admin.post('/models/:id/questions', h(async (req, res) => {
  const q = parseQuestion(req.body);
  if (q.error) return fail(res, 400, q.error);
  const { rows } = await pool.query('insert into questions(model_id, text, options, correct, explanation) values($1,$2,$3,$4,$5) returning *',
    [+req.params.id, q.text, JSON.stringify(q.options), q.correct, q.explanation]);
  res.json(rows[0]);
}));
admin.put('/questions/:id', h(async (req, res) => {
  const q = parseQuestion(req.body);
  if (q.error) return fail(res, 400, q.error);
  const { rows } = await pool.query('update questions set text=$1, options=$2, correct=$3, explanation=$4 where id=$5 returning *',
    [q.text, JSON.stringify(q.options), q.correct, q.explanation, +req.params.id]);
  rows[0] ? res.json(rows[0]) : fail(res, 404, 'السؤال غير موجود');
}));
admin.delete('/questions/:id', h(async (req, res) => {
  await pool.query('delete from questions where id=$1', [+req.params.id]);
  res.json({ ok: true });
}));
app.use('/api/admin', admin);

app.use('/api', (req, res) => fail(res, 404, 'مسار غير موجود'));
app.use((err, req, res, next) => {
  console.error(err);
  fail(res, 500, 'حصل خطأ في السيرفر');
});

/* ---------- قاعدة البيانات ---------- */
async function initDb() {
  await pool.query(`
    create table if not exists users (
      id serial primary key, name text not null, email text unique not null,
      password_hash text not null, role text not null default 'student',
      created_at timestamptz not null default now());
    create table if not exists units (
      id serial primary key, title text not null, description text not null default '');
    create table if not exists models (
      id serial primary key, unit_id int not null references units(id) on delete cascade,
      title text not null, minutes int not null default 10);
    create table if not exists questions (
      id serial primary key, model_id int not null references models(id) on delete cascade,
      text text not null, options jsonb not null, correct int not null, explanation text not null default '');
    create table if not exists attempts (
      id serial primary key, user_id int not null references users(id) on delete cascade,
      model_id int not null references models(id) on delete cascade,
      score int not null, total int not null, answers jsonb not null,
      created_at timestamptz not null default now());
    create index if not exists attempts_user_model on attempts(user_id, model_id);
  `);

  const { rows } = await pool.query('select count(*)::int n from units');
  if (rows[0].n === 0) {
    for (const u of seed) {
      const ur = await pool.query('insert into units(title, description) values($1,$2) returning id', [u.title, u.description]);
      for (const m of u.models) {
        const mr = await pool.query('insert into models(unit_id, title, minutes) values($1,$2,$3) returning id', [ur.rows[0].id, m.title, m.minutes]);
        for (const q of m.questions) {
          await pool.query('insert into questions(model_id, text, options, correct, explanation) values($1,$2,$3,$4,$5)',
            [mr.rows[0].id, q.text, JSON.stringify(q.options), q.correct, q.explanation]);
        }
      }
    }
    console.log('تم إضافة البيانات التجريبية');
  }

  const ae = clean(process.env.ADMIN_EMAIL).toLowerCase(), ap = process.env.ADMIN_PASSWORD;
  if (ae && ap) {
    const ex = await pool.query('select id from users where email=$1', [ae]);
    if (ex.rowCount) {
      await pool.query("update users set role='teacher' where email=$1", [ae]);
    } else {
      await pool.query("insert into users(name,email,password_hash,role) values($1,$2,$3,'teacher')", ['المدرس', ae, await bcrypt.hash(ap, 10)]);
      console.log('تم إنشاء حساب المدرس:', ae);
    }
  } else {
    console.warn('تنبيه: ADMIN_EMAIL و ADMIN_PASSWORD مش متحددين، فمفيش حساب مدرس');
  }
}

initDb()
  .then(() => app.listen(PORT, () => console.log('الموقع شغال على المنفذ ' + PORT)))
  .catch(e => { console.error('فشل تجهيز قاعدة البيانات:', e); process.exit(1); });
