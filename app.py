import os, secrets, datetime, threading, time
from flask import Flask, request, jsonify, session, redirect, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, origins="*", supports_credentials=True)

DATABASE_URL = os.environ.get('DATABASE_URL')

# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    verified INTEGER DEFAULT 1,
                    banned_until TIMESTAMP DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                DROP TABLE IF EXISTS messages;
                CREATE TABLE IF NOT EXISTS tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender_id INTEGER,
                    sender_name TEXT,
                    receiver_id INTEGER,
                    content TEXT,
                    media_type TEXT DEFAULT NULL,
                    media_data TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            cur.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS receiver_id INTEGER;')
            cur.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_id INTEGER;')
            cur.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_name TEXT;')
            cur.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_type TEXT;')
            cur.execute('ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_data TEXT;')
        conn.commit()

# ── Nettoyage auto après 24h ──────────────────────────────────────────────────
def cleanup_old_messages():
    while True:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
                    cur.execute('DELETE FROM messages WHERE created_at < %s', (cutoff,))
                conn.commit()
        except Exception as e:
            print(f"Cleanup error: {e}")
        time.sleep(3600)  # toutes les heures

# ── État serveur ──────────────────────────────────────────────────────────────
server_state = {
    'status': 'open',
    'emergency_message': 'Le service est temporairement indisponible.',
    'pause_message': 'Le chat est en pause. Revenez dans quelques instants.',
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def check_token(token):
    if not token: return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'SELECT u.* FROM tokens t JOIN users u ON t.user_id=u.id WHERE t.token=%s AND t.expires_at>%s',
                (token, datetime.datetime.utcnow())
            )
            return cur.fetchone()

def is_banned(user):
    if not user['banned_until']: return False
    return datetime.datetime.utcnow() < user['banned_until']

def check_server():
    if server_state['status'] == 'emergency': return False, server_state['emergency_message']
    if server_state['status'] == 'paused':    return False, server_state['pause_message']
    return True, None

def auth_check(request):
    token = request.headers.get('X-Token')
    user = check_token(token)
    if not user: return None, jsonify({'error': 'Non authentifié.'}), 401
    ok, msg = check_server()
    if not ok: return None, jsonify({'error': msg, 'server_status': server_state['status']}), 503
    if is_banned(user): return None, jsonify({'error': 'Tu es banni temporairement.'}), 403
    return user, None, None

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not username or not email or not password:
        return jsonify({'error': 'Tous les champs sont requis.'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Pseudo trop court (min 3 caractères).'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (min 6 caractères).'}), 400
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO users (username,email,password,verified) VALUES (%s,%s,%s,1) RETURNING id',
                    (username, email, generate_password_hash(password))
                )
            conn.commit()
        return jsonify({'success': True})
    except Exception:
        return jsonify({'error': 'Pseudo ou email déjà utilisé.'}), 409

@app.route('/api/login', methods=['POST'])
def login():
    data  = request.get_json()
    email = data.get('email', '').strip().lower()
    pwd   = data.get('password', '')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM users WHERE email=%s', (email,))
            user = cur.fetchone()
    if not user or not check_password_hash(user['password'], pwd):
        return jsonify({'error': 'Email ou mot de passe incorrect.'}), 401
    if is_banned(user):
        remaining = int((user['banned_until'] - datetime.datetime.utcnow()).total_seconds() // 60)
        return jsonify({'error': f'Tu es banni encore {remaining} minute(s).'}), 403
    token   = secrets.token_urlsafe(48)
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO tokens (user_id,token,expires_at) VALUES (%s,%s,%s)', (user['id'], token, expires))
        conn.commit()
    return jsonify({'success': True, 'token': token, 'username': user['username'], 'user_id': user['id']})

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('X-Token')
    if token:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM tokens WHERE token=%s', (token,))
            conn.commit()
    return jsonify({'success': True})

@app.route('/api/me')
def me():
    user, err, code = auth_check(request)
    if err: return err, code
    return jsonify({'username': user['username'], 'user_id': user['id']})

# ── Utilisateurs ──────────────────────────────────────────────────────────────
@app.route('/api/users')
def get_users():
    user, err, code = auth_check(request)
    if err: return err, code
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id, username FROM users WHERE id != %s ORDER BY username ASC', (user['id'],))
            users = cur.fetchall()
    return jsonify({'users': [dict(u) for u in users]})

# ── Messages privés ───────────────────────────────────────────────────────────
@app.route('/api/messages/<int:other_id>')
def get_messages(other_id):
    user, err, code = auth_check(request)
    if err: return err, code
    since = request.args.get('since', 0)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT id, sender_id, sender_name, content, media_type, media_data, created_at
                FROM messages
                WHERE id > %s AND (
                    (sender_id=%s AND receiver_id=%s) OR
                    (sender_id=%s AND receiver_id=%s)
                )
                ORDER BY id ASC LIMIT 100
            ''', (since, user['id'], other_id, other_id, user['id']))
            rows = cur.fetchall()
    return jsonify({'messages': [{
        'id':          r['id'],
        'sender_id':   r['sender_id'],
        'sender_name': r['sender_name'],
        'content':     r['content'],
        'media_type':  r['media_type'],
        'media_data':  r['media_data'],
        'created_at':  r['created_at'].isoformat()
    } for r in rows]})

@app.route('/api/send/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    user, err, code = auth_check(request)
    if err: return err, code
    data       = request.get_json()
    content    = data.get('content', '').strip()
    media_type = data.get('media_type')   # 'image', 'gif', 'video'
    media_data = data.get('media_data')   # base64

    if not content and not media_data:
        return jsonify({'error': 'Message vide.'}), 400
    if content and len(content) > 500:
        return jsonify({'error': 'Message trop long.'}), 400
    if media_data and len(media_data) > 20_000_000:  # 20MB max
        return jsonify({'error': 'Fichier trop lourd (max 20MB).'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'INSERT INTO messages (sender_id,sender_name,receiver_id,content,media_type,media_data) VALUES (%s,%s,%s,%s,%s,%s)',
                (user['id'], user['username'], receiver_id, content or None, media_type, media_data)
            )
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/status')
def status():
    return jsonify(server_state)

# ── Dashboard admin ───────────────────────────────────────────────────────────
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin1234')

ADMIN_CSS = """<style>
:root{--bg:#0e0c1a;--bg2:#16132a;--bg3:#1e1a35;--purple:#7c5cbf;--purple-l:#a07ee0;--border:#2e2850;--red:#c0392b;--red-dim:#7a1f16;--green:#27ae60;--amber:#d4a017;--text:#e8e3f0;--text-dim:#9b93b5;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;min-height:100vh;}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;justify-content:space-between;}
header h1{font-size:18px;font-weight:600;color:var(--purple-l);}
header a{color:var(--text-dim);text-decoration:none;font-size:13px;}
.main{max-width:1100px;margin:0 auto;padding:32px 24px;}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px;}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px 24px;}
.stat-card .label{font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;}
.stat-card .value{font-size:32px;font-weight:700;color:var(--purple-l);}
.stat-card.status .value{font-size:18px;}
.open{color:var(--green)!important;}.paused{color:var(--amber)!important;}.emergency{color:var(--red)!important;}
.section{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;}
.section h2{font-size:14px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;}
.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;}
form{display:inline;}
button{cursor:pointer;border:none;border-radius:8px;padding:10px 20px;font-size:13px;font-weight:600;font-family:inherit;transition:opacity .15s;}
button:hover{opacity:.85;}
.btn-emergency{background:var(--red);color:#fff;}
.btn-pause{background:var(--amber);color:#000;}
.btn-resume{background:var(--green);color:#fff;}
.btn-danger{background:var(--red-dim);color:#f8a;border:1px solid var(--red);font-size:12px;padding:6px 12px;}
.btn-secondary{background:var(--bg3);color:var(--text);border:1px solid var(--border);font-size:12px;padding:6px 12px;}
.btn-activate{background:#1a3d2e;color:#4ade80;border:1px solid #27ae60;font-size:12px;padding:6px 12px;}
.emergency-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.emergency-form input{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 14px;font-size:13px;width:300px;font-family:inherit;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:10px 14px;color:var(--text-dim);font-size:11px;text-transform:uppercase;border-bottom:1px solid var(--border);}
td{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-ok{background:#1a3d2e;color:#4ade80;}.badge-pending{background:#2d2416;color:#fbbf24;}.badge-banned{background:#3d1515;color:#f87171;}
.ban-form{display:flex;gap:6px;align-items:center;}
.ban-form input[type=number]{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:5px 8px;width:56px;font-size:12px;font-family:inherit;}
.username-cell{font-weight:600;color:var(--purple-l);}.email-cell{color:var(--text-dim);}.date-cell{color:var(--text-dim);font-size:12px;}
input[type=password]{width:100%;background:#0e0c1a;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:12px 14px;font-size:14px;font-family:inherit;margin-bottom:20px;}
input:focus{outline:none;border-color:var(--purple);}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:40px;width:360px;}
.auth-wrap{height:100vh;display:flex;align-items:center;justify-content:center;}
.error-box{background:#2d1515;border:1px solid var(--red);color:#f87171;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:20px;}
label{display:block;font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;}
.btn-main{width:100%;background:var(--purple);color:#fff;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;}
</style>"""

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin'): return redirect('/admin/login')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,username,email,verified,banned_until,created_at FROM users ORDER BY id DESC')
            users = cur.fetchall()
            cur.execute('SELECT COUNT(*) as c FROM messages')
            msg_count = cur.fetchone()['c']
            cur.execute('SELECT COUNT(*) as c FROM users')
            user_count = cur.fetchone()['c']

    st = server_state['status']
    status_label = {'open': 'Ouvert', 'paused': 'En pause', 'emergency': "Arrêt d'urgence"}.get(st, st)

    rows_html = ''
    for u in users:
        banned = u['banned_until'] and datetime.datetime.utcnow() < u['banned_until']
        if banned:
            badge  = '<span class="badge badge-banned">Banni</span>'
            action = f'<form action="/admin/unban/{u["id"]}" method="post" style="display:inline"><button class="btn-secondary">Débannir</button></form>'
        elif u['verified']:
            badge  = '<span class="badge badge-ok">Actif</span>'
            action = f'<form action="/admin/ban/{u["id"]}" method="post" class="ban-form"><input type="number" name="duration" value="10" min="1" max="1440"><span style="font-size:11px;color:var(--text-dim)">min</span><button class="btn-danger">Bannir</button></form>'
        else:
            badge  = '<span class="badge badge-pending">En attente</span>'
            action = f'<form action="/admin/verify/{u["id"]}" method="post" style="display:inline"><button class="btn-activate">Activer</button></form>'
        date = str(u['created_at'])[:10] if u['created_at'] else ''
        rows_html += f'<tr><td class="date-cell">{u["id"]}</td><td class="username-cell">{u["username"]}</td><td class="email-cell">{u["email"]}</td><td>{badge}</td><td class="date-cell">{date}</td><td>{action}</td></tr>'

    resume_btn = '' if st == 'open'      else '<form action="/admin/resume" method="post"><button class="btn-resume">Rouvrir le chat</button></form>'
    pause_btn  = '' if st == 'paused'    else '<form action="/admin/pause" method="post"><button class="btn-pause">Mettre en pause</button></form>'
    emerg_btn  = '' if st == 'emergency' else f'<form action="/admin/emergency" method="post" class="emergency-form"><input type="text" name="message" placeholder="Message d\'urgence" value="{server_state["emergency_message"]}"><button class="btn-emergency">Arrêt d\'urgence</button></form>'

    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Dashboard Admin</title>{ADMIN_CSS}</head><body>
<header><h1>Dashboard Admin</h1><a href="/admin/logout">Déconnexion</a></header>
<div class="main">
<div class="stats">
  <div class="stat-card"><div class="label">Utilisateurs</div><div class="value">{user_count}</div></div>
  <div class="stat-card"><div class="label">Messages (24h)</div><div class="value">{msg_count}</div></div>
  <div class="stat-card status"><div class="label">Statut</div><div class="value {st}">{status_label}</div></div>
</div>
<div class="section"><h2>Contrôles serveur</h2><div class="controls">{resume_btn}{pause_btn}{emerg_btn}</div></div>
<div class="section"><h2>Utilisateurs</h2>
<table><thead><tr><th>#</th><th>Pseudo</th><th>Email</th><th>Statut</th><th>Inscrit le</th><th>Actions</th></tr></thead>
<tbody>{rows_html if rows_html else '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-dim)">Aucun utilisateur</td></tr>'}</tbody></table>
</div></div></body></html>"""
    return Response(html, mimetype='text/html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = ''
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin')
        error = '<div class="error-box">Mot de passe incorrect.</div>'
    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Admin</title>{ADMIN_CSS}</head><body>
<div class="auth-wrap"><div class="card">
<h1 style="font-size:20px;color:var(--purple-l);margin-bottom:8px">Dashboard Admin</h1>
<p style="color:var(--text-dim);font-size:13px;margin-bottom:24px">Accès réservé</p>
{error}<form method="post"><label>Mot de passe</label><input type="password" name="password" autofocus>
<button class="btn-main">Se connecter</button></form>
</div></div></body></html>"""
    return Response(html, mimetype='text/html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect('/admin/login')

@app.route('/admin/emergency', methods=['POST'])
def admin_emergency():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'emergency'
    server_state['emergency_message'] = request.form.get('message', server_state['emergency_message'])
    return redirect('/admin')

@app.route('/admin/pause', methods=['POST'])
def admin_pause():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'paused'
    return redirect('/admin')

@app.route('/admin/resume', methods=['POST'])
def admin_resume():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'open'
    return redirect('/admin')

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
def admin_ban(user_id):
    if not session.get('admin'): return 'Non autorisé', 403
    duration = int(request.form.get('duration', 10))
    banned_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=duration)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET banned_until=%s WHERE id=%s', (banned_until, user_id))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/unban/<int:user_id>', methods=['POST'])
def admin_unban(user_id):
    if not session.get('admin'): return 'Non autorisé', 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET banned_until=NULL WHERE id=%s', (user_id,))
        conn.commit()
    return redirect('/admin')

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
def admin_verify(user_id):
    if not session.get('admin'): return 'Non autorisé', 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET verified=1 WHERE id=%s', (user_id,))
        conn.commit()
    return redirect('/admin')

# ── Démarrage ─────────────────────────────────────────────────────────────────
try:
    init_db()
    print("Base de données initialisée !")
    t = threading.Thread(target=cleanup_old_messages, daemon=True)
    t.start()
    print("Nettoyage automatique démarré !")
except Exception as e:
    print(f"Erreur démarrage: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
