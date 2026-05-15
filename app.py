import os, secrets, datetime, threading, time, json
from flask import Flask, request, jsonify, session, redirect, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, origins="*", supports_credentials=True)

DATABASE_URL = os.environ.get('DATABASE_URL')
ADMIN_USERS  = {'raphetsoso', 'romain'}

# ── WebRTC signaling store (in-memory) ───────────────────────────────────────
# { group_id: { user_id: { 'username': str, 'muted': bool, 'offer': ..., 'answer': ..., 'candidates': [] } } }
voice_rooms = {}
voice_lock  = threading.Lock()

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

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
                    avatar TEXT DEFAULT NULL,
                    accent_color TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
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
                    group_id INTEGER DEFAULT NULL,
                    content TEXT,
                    media_type TEXT DEFAULT NULL,
                    media_data TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS friends (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    friend_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'accepted',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, friend_id)
                );
                CREATE TABLE IF NOT EXISTS groups (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS group_members (
                    id SERIAL PRIMARY KEY,
                    group_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT DEFAULT 'member',
                    muted_until TIMESTAMP DEFAULT NULL,
                    UNIQUE(group_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS saved_messages (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    content TEXT,
                    sender_name TEXT,
                    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                );
                CREATE TABLE IF NOT EXISTS message_reads (
                    message_id INTEGER NOT NULL,
                    user_id    INTEGER NOT NULL,
                    read_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (message_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS typing_status (
                    user_id    INTEGER NOT NULL,
                    chat_with  INTEGER,
                    group_id   INTEGER,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id)
                );
            ''')
            # Migrations
            for table, col, definition in [
                ('users',        'avatar',       'TEXT DEFAULT NULL'),
                ('users',        'accent_color', 'TEXT DEFAULT NULL'),
                ('messages',     'group_id',     'INTEGER DEFAULT NULL'),
                ('messages',     'receiver_id',  'INTEGER'),
                ('messages',     'sender_id',    'INTEGER'),
                ('messages',     'sender_name',  'TEXT'),
                ('messages',     'media_type',   'TEXT'),
                ('messages',     'media_data',   'TEXT'),
                ('group_members','role',         "TEXT DEFAULT 'member'"),
                ('group_members','muted_until',  'TIMESTAMP DEFAULT NULL'),
            ]:
                try:
                    cur.execute(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition};')
                except Exception: pass
        conn.commit()

def cleanup_loop():
    while True:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
                    cur.execute('DELETE FROM messages WHERE created_at < %s', (cutoff,))
                conn.commit()
        except Exception as e:
            print(f'Cleanup error: {e}')
        time.sleep(3600)

# ── État serveur ──────────────────────────────────────────────────────────────
server_state = {
    'status': 'open',
    'emergency_message': 'Le service est temporairement indisponible.',
    'pause_message': 'Le chat est en pause.',
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

def is_admin(user): return user['username'].lower() in ADMIN_USERS

def check_server():
    if server_state['status'] == 'emergency': return False, server_state['emergency_message']
    if server_state['status'] == 'paused':    return False, server_state['pause_message']
    return True, None

def auth_check(req):
    token = req.headers.get('X-Token')
    user  = check_token(token)
    if not user: return None, (jsonify({'error': 'Non authentifié.'}), 401)
    ok, msg = check_server()
    if not ok: return None, (jsonify({'error': msg, 'server_status': server_state['status']}), 503)
    if is_banned(user): return None, (jsonify({'error': 'Tu es banni temporairement.'}), 403)
    return user, None

def is_group_mod(user_id, group_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM group_members WHERE group_id=%s AND user_id=%s", (group_id, user_id))
            row = cur.fetchone()
            return row and row['role'] in ('moderator', 'admin')

def is_muted_in_group(user_id, group_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT muted_until FROM group_members WHERE group_id=%s AND user_id=%s", (group_id, user_id))
            row = cur.fetchone()
            if not row or not row['muted_until']: return False
            return datetime.datetime.utcnow() < row['muted_until']

def serialize_messages(rows, include_color=False):
    result = []
    for r in rows:
        m = {'id': r['id'], 'sender_id': r['sender_id'], 'sender_name': r['sender_name'],
             'content': r['content'], 'media_type': r['media_type'], 'media_data': r['media_data'],
             'created_at': r['created_at'].isoformat() if r['created_at'] else ''}
        if include_color: m['accent_color'] = r.get('accent_color')
        result.append(m)
    return result

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json() or {}
    username = d.get('username','').strip()
    email    = d.get('email','').strip().lower()
    password = d.get('password','')
    if not all([username, email, password]):
        return jsonify({'error': 'Tous les champs sont requis.'}), 400
    if len(username) < 3: return jsonify({'error': 'Pseudo trop court.'}), 400
    if len(password) < 6: return jsonify({'error': 'Mot de passe trop court.'}), 400
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO users (username,email,password,verified) VALUES (%s,%s,%s,1)',
                            (username, email, generate_password_hash(password)))
            conn.commit()
        return jsonify({'success': True})
    except Exception:
        return jsonify({'error': 'Pseudo ou email déjà utilisé.'}), 409

@app.route('/api/login', methods=['POST'])
def login():
    d     = request.get_json() or {}
    email = d.get('email','').strip().lower()
    pwd   = d.get('password','')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM users WHERE email=%s', (email,))
            user = cur.fetchone()
    if not user or not check_password_hash(user['password'], pwd):
        return jsonify({'error': 'Email ou mot de passe incorrect.'}), 401
    if is_banned(user):
        remaining = int((user['banned_until'] - datetime.datetime.utcnow()).total_seconds() // 60)
        return jsonify({'error': f'Banni encore {remaining} min.'}), 403
    token   = secrets.token_urlsafe(48)
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO tokens (user_id,token,expires_at) VALUES (%s,%s,%s)', (user['id'], token, expires))
        conn.commit()
    return jsonify({'success': True, 'token': token, 'username': user['username'],
                    'user_id': user['id'], 'is_admin': is_admin(user),
                    'avatar': user.get('avatar'), 'accent_color': user.get('accent_color')})

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
    user, err = auth_check(request)
    if err: return err
    return jsonify({'username': user['username'], 'user_id': user['id'],
                    'is_admin': is_admin(user), 'avatar': user.get('avatar'),
                    'accent_color': user.get('accent_color')})

# ── Profil ────────────────────────────────────────────────────────────────────
@app.route('/api/rename', methods=['POST'])
def rename():
    user, err = auth_check(request)
    if err: return err
    username = (request.get_json() or {}).get('username','').strip()
    if len(username) < 3: return jsonify({'error': 'Pseudo trop court.'}), 400
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE users SET username=%s WHERE id=%s', (username, user['id']))
                cur.execute('UPDATE messages SET sender_name=%s WHERE sender_id=%s', (username, user['id']))
            conn.commit()
        return jsonify({'success': True})
    except Exception:
        return jsonify({'error': 'Pseudo déjà utilisé.'}), 409

@app.route('/api/avatar', methods=['POST'])
def update_avatar():
    user, err = auth_check(request)
    if err: return err
    data   = request.get_json() or {}
    avatar = data.get('avatar')
    if avatar and len(str(avatar)) > 5_000_000:
        return jsonify({'error': 'Image trop lourde (max 5MB).'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET avatar=%s WHERE id=%s', (avatar, user['id']))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/accent', methods=['POST'])
def update_accent():
    user, err = auth_check(request)
    if err: return err
    color = (request.get_json() or {}).get('color', '')
    if color and (len(color) != 7 or not color.startswith('#')):
        return jsonify({'error': 'Couleur invalide.'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET accent_color=%s WHERE id=%s', (color or None, user['id']))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            for q, p in [
                ('DELETE FROM tokens WHERE user_id=%s', (user['id'],)),
                ('DELETE FROM messages WHERE sender_id=%s OR receiver_id=%s', (user['id'], user['id'])),
                ('DELETE FROM friends WHERE user_id=%s OR friend_id=%s', (user['id'], user['id'])),
                ('DELETE FROM group_members WHERE user_id=%s', (user['id'],)),
                ('DELETE FROM users WHERE id=%s', (user['id'],)),
            ]:
                cur.execute(q, p)
        conn.commit()
    return jsonify({'success': True})

# ── Users ─────────────────────────────────────────────────────────────────────
@app.route('/api/users')
def get_users():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id, username, avatar FROM users WHERE id != %s ORDER BY username ASC', (user['id'],))
            rows = cur.fetchall()
    return jsonify({'users': [{'id': r['id'], 'username': r['username'], 'avatar': r.get('avatar')} for r in rows]})

# ── Amis ──────────────────────────────────────────────────────────────────────
@app.route('/api/friends')
def get_friends():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT u.id, u.username, u.avatar FROM users u WHERE u.id IN (
                    SELECT f1.friend_id FROM friends f1
                    JOIN friends f2 ON f1.user_id=f2.friend_id AND f1.friend_id=f2.user_id
                    WHERE f1.user_id=%s)''', (user['id'],))
            friends = cur.fetchall()
            cur.execute('''SELECT u.id, u.username FROM users u JOIN friends f ON f.friend_id=u.id
                WHERE f.user_id=%s AND NOT EXISTS (SELECT 1 FROM friends WHERE user_id=f.friend_id AND friend_id=%s)''',
                (user['id'], user['id']))
            sent = cur.fetchall()
            cur.execute('''SELECT u.id, u.username FROM users u JOIN friends f ON f.user_id=u.id
                WHERE f.friend_id=%s AND NOT EXISTS (SELECT 1 FROM friends WHERE user_id=%s AND friend_id=f.user_id)''',
                (user['id'], user['id']))
            received = cur.fetchall()
    return jsonify({
        'friends':  [{'id': r['id'], 'username': r['username'], 'avatar': r.get('avatar')} for r in friends],
        'sent':     [{'id': r['id'], 'username': r['username']} for r in sent],
        'received': [{'id': r['id'], 'username': r['username']} for r in received],
    })

@app.route('/api/friends/add/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    user, err = auth_check(request)
    if err: return err
    if user['id'] == friend_id: return jsonify({'error': 'Tu ne peux pas t\'ajouter toi-même.'}), 400
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO friends (user_id,friend_id,status) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                            (user['id'], friend_id, 'accepted'))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/friends/remove/<int:friend_id>', methods=['POST'])
def remove_friend(friend_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM friends WHERE (user_id=%s AND friend_id=%s) OR (user_id=%s AND friend_id=%s)',
                        (user['id'], friend_id, friend_id, user['id']))
        conn.commit()
    return jsonify({'success': True})

# ── Messages privés ───────────────────────────────────────────────────────────
@app.route('/api/messages/<int:other_id>')
def get_messages(other_id):
    user, err = auth_check(request)
    if err: return err
    since = request.args.get('since', 0)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT id,sender_id,sender_name,content,media_type,media_data,created_at
                FROM messages WHERE id>%s AND group_id IS NULL AND (
                    (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s))
                ORDER BY id ASC LIMIT 100''',
                (since, user['id'], other_id, other_id, user['id']))
            rows = cur.fetchall()
    return jsonify({'messages': serialize_messages(rows)})

@app.route('/api/send/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    user, err = auth_check(request)
    if err: return err
    # Vérifie amitié
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT 1 FROM friends f1 JOIN friends f2
                ON f1.user_id=f2.friend_id AND f1.friend_id=f2.user_id
                WHERE f1.user_id=%s AND f1.friend_id=%s''', (user['id'], receiver_id))
            if not cur.fetchone():
                return jsonify({'error': 'Tu dois être ami pour écrire.'}), 403
    d = request.get_json() or {}
    content    = (d.get('content') or '').strip()
    media_type = d.get('media_type')
    media_data = d.get('media_data')
    if not content and not media_data: return jsonify({'error': 'Message vide.'}), 400
    if content and len(content) > 500: return jsonify({'error': 'Trop long.'}), 400
    if media_data and len(str(media_data)) > 20_000_000: return jsonify({'error': 'Trop lourd.'}), 400
    # Limites quotidiennes
    if not is_admin(user):
        today = datetime.datetime.utcnow().date()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) as c FROM messages WHERE sender_id=%s AND created_at>=%s AND group_id IS NULL', (user['id'], today))
                if cur.fetchone()['c'] >= 50: return jsonify({'error': 'Limite 50 messages/jour atteinte.'}), 429
                if media_type in ('image','gif'):
                    cur.execute("SELECT COUNT(*) as c FROM messages WHERE sender_id=%s AND created_at>=%s AND media_type IN ('image','gif')", (user['id'], today))
                    if cur.fetchone()['c'] >= 8: return jsonify({'error': 'Limite 8 images/jour atteinte.'}), 429
                if media_type == 'video':
                    cur.execute("SELECT COUNT(*) as c FROM messages WHERE sender_id=%s AND created_at>=%s AND media_type='video'", (user['id'], today))
                    if cur.fetchone()['c'] >= 8: return jsonify({'error': 'Limite 8 vidéos/jour atteinte.'}), 429
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO messages (sender_id,sender_name,receiver_id,content,media_type,media_data) VALUES (%s,%s,%s,%s,%s,%s)',
                        (user['id'], user['username'], receiver_id, content or None, media_type, media_data))
        conn.commit()
    return jsonify({'success': True})

# ── Groupes ───────────────────────────────────────────────────────────────────
@app.route('/api/groups')
def get_groups():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT g.id, g.name, g.creator_id,
                (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count
                FROM groups g JOIN group_members gm ON gm.group_id=g.id
                WHERE gm.user_id=%s ORDER BY g.created_at DESC''', (user['id'],))
            groups = cur.fetchall()
    return jsonify({'groups': [dict(g) for g in groups]})

@app.route('/api/groups/create', methods=['POST'])
def create_group():
    user, err = auth_check(request)
    if err: return err
    d       = request.get_json() or {}
    name    = (d.get('name') or '').strip()
    members = d.get('members', [])
    if not name: return jsonify({'error': 'Nom requis.'}), 400
    if len(members) > 9: return jsonify({'error': 'Max 10 membres.'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            for mid in members:
                cur.execute('''SELECT 1 FROM friends f1 JOIN friends f2
                    ON f1.user_id=f2.friend_id AND f1.friend_id=f2.user_id
                    WHERE f1.user_id=%s AND f1.friend_id=%s''', (user['id'], mid))
                if not cur.fetchone(): return jsonify({'error': 'Certains membres ne sont pas tes amis.'}), 400
            cur.execute('INSERT INTO groups (name,creator_id) VALUES (%s,%s) RETURNING id', (name, user['id']))
            group_id = cur.fetchone()['id']
            for mid in set([user['id']] + members):
                role = 'admin' if mid == user['id'] else 'member'
                cur.execute('INSERT INTO group_members (group_id,user_id,role) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                            (group_id, mid, role))
        conn.commit()
    return jsonify({'success': True, 'group_id': group_id})

@app.route('/api/groups/<int:group_id>/messages')
def get_group_messages(group_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s', (group_id, user['id']))
            if not cur.fetchone(): return jsonify({'error': 'Non membre.'}), 403
            since = request.args.get('since', 0)
            cur.execute('''SELECT m.id,m.sender_id,m.sender_name,m.content,m.media_type,m.media_data,m.created_at,u.accent_color
                FROM messages m LEFT JOIN users u ON u.id=m.sender_id
                WHERE m.group_id=%s AND m.id>%s ORDER BY m.id ASC LIMIT 100''', (group_id, since))
            rows = cur.fetchall()
    return jsonify({'messages': serialize_messages(rows, include_color=True)})

@app.route('/api/groups/<int:group_id>/send', methods=['POST'])
def send_group_message(group_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s', (group_id, user['id']))
            if not cur.fetchone(): return jsonify({'error': 'Non membre.'}), 403
            cur.execute('SELECT u.username FROM users u JOIN group_members gm ON gm.user_id=u.id WHERE gm.group_id=%s', (group_id,))
            group_has_admin = any(r['username'].lower() in ADMIN_USERS for r in cur.fetchall())
    if is_muted_in_group(user['id'], group_id):
        return jsonify({'error': 'Tu es muté dans ce groupe.'}), 403
    d = request.get_json() or {}
    content    = (d.get('content') or '').strip()
    media_type = d.get('media_type')
    media_data = d.get('media_data')
    if not content and not media_data: return jsonify({'error': 'Message vide.'}), 400
    if media_data and len(str(media_data)) > 20_000_000: return jsonify({'error': 'Trop lourd.'}), 400
    if not is_admin(user) and not group_has_admin:
        today = datetime.datetime.utcnow().date()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) as c FROM messages WHERE sender_id=%s AND created_at>=%s AND group_id IS NOT NULL', (user['id'], today))
                if cur.fetchone()['c'] >= 50: return jsonify({'error': 'Limite 50 messages/jour.'}), 429
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO messages (sender_id,sender_name,group_id,content,media_type,media_data) VALUES (%s,%s,%s,%s,%s,%s)',
                        (user['id'], user['username'], group_id, content or None, media_type, media_data))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<int:group_id>/members')
def get_group_members(group_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s', (group_id, user['id']))
            if not cur.fetchone(): return jsonify({'error': 'Non membre.'}), 403
            cur.execute('''SELECT u.id, u.username, u.avatar, u.accent_color, gm.role, gm.muted_until
                FROM users u JOIN group_members gm ON gm.user_id=u.id
                WHERE gm.group_id=%s''', (group_id,))
            members = cur.fetchall()
    return jsonify({'members': [{
        'id': m['id'], 'username': m['username'], 'avatar': m.get('avatar'),
        'accent_color': m.get('accent_color'), 'role': m['role'],
        'muted': bool(m['muted_until'] and datetime.datetime.utcnow() < m['muted_until'])
    } for m in members]})

# ── Modération ────────────────────────────────────────────────────────────────
@app.route('/api/groups/<int:group_id>/promote/<int:target_id>', methods=['POST'])
def promote_moderator(group_id, target_id):
    user, err = auth_check(request)
    if err: return err
    if not is_admin(user) and not is_group_mod(user['id'], group_id):
        return jsonify({'error': 'Non autorisé.'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE group_members SET role='moderator' WHERE group_id=%s AND user_id=%s", (group_id, target_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<int:group_id>/demote/<int:target_id>', methods=['POST'])
def demote_moderator(group_id, target_id):
    user, err = auth_check(request)
    if err: return err
    if not is_admin(user) and not is_group_mod(user['id'], group_id):
        return jsonify({'error': 'Non autorisé.'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE group_members SET role='member' WHERE group_id=%s AND user_id=%s", (group_id, target_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<int:group_id>/mute/<int:target_id>', methods=['POST'])
def mute_member(group_id, target_id):
    user, err = auth_check(request)
    if err: return err
    if not is_admin(user) and not is_group_mod(user['id'], group_id):
        return jsonify({'error': 'Non autorisé.'}), 403
    duration    = int((request.get_json() or {}).get('duration', 10))
    muted_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=duration)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE group_members SET muted_until=%s WHERE group_id=%s AND user_id=%s',
                        (muted_until, group_id, target_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<int:group_id>/unmute/<int:target_id>', methods=['POST'])
def unmute_member(group_id, target_id):
    user, err = auth_check(request)
    if err: return err
    if not is_admin(user) and not is_group_mod(user['id'], group_id):
        return jsonify({'error': 'Non autorisé.'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE group_members SET muted_until=NULL WHERE group_id=%s AND user_id=%s',
                        (group_id, target_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/groups/<int:group_id>/kick/<int:target_id>', methods=['POST'])
def kick_member(group_id, target_id):
    user, err = auth_check(request)
    if err: return err
    if not is_admin(user) and not is_group_mod(user['id'], group_id):
        return jsonify({'error': 'Non autorisé.'}), 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM group_members WHERE group_id=%s AND user_id=%s', (group_id, target_id))
        conn.commit()
    return jsonify({'success': True})

# ── WebRTC Signaling ──────────────────────────────────────────────────────────
@app.route('/api/voice/<int:group_id>/join', methods=['POST'])
def voice_join(group_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT 1 FROM group_members WHERE group_id=%s AND user_id=%s', (group_id, user['id']))
            if not cur.fetchone(): return jsonify({'error': 'Non membre.'}), 403
    with voice_lock:
        if group_id not in voice_rooms: voice_rooms[group_id] = {}
        voice_rooms[group_id][user['id']] = {
            'username': user['username'], 'muted': False,
            'offers': {}, 'answers': {}, 'candidates': {}
        }
        peers = [{'id': uid, 'username': info['username'], 'muted': info['muted']}
                 for uid, info in voice_rooms[group_id].items() if uid != user['id']]
    return jsonify({'success': True, 'peers': peers, 'my_id': user['id']})

@app.route('/api/voice/<int:group_id>/leave', methods=['POST'])
def voice_leave(group_id):
    user, err = auth_check(request)
    if err: return err
    with voice_lock:
        if group_id in voice_rooms and user['id'] in voice_rooms[group_id]:
            del voice_rooms[group_id][user['id']]
            if not voice_rooms[group_id]: del voice_rooms[group_id]
    return jsonify({'success': True})

@app.route('/api/voice/<int:group_id>/peers')
def voice_peers(group_id):
    user, err = auth_check(request)
    if err: return err
    with voice_lock:
        room = voice_rooms.get(group_id, {})
        peers = [{'id': uid, 'username': info['username'], 'muted': info['muted']}
                 for uid, info in room.items()]
    return jsonify({'peers': peers})

@app.route('/api/voice/<int:group_id>/signal', methods=['POST'])
def voice_signal(group_id):
    """Exchange WebRTC signals (offer/answer/candidate)"""
    user, err = auth_check(request)
    if err: return err
    d      = request.get_json() or {}
    target = d.get('target_id')
    stype  = d.get('type')   # 'offer', 'answer', 'candidate'
    data   = d.get('data')
    with voice_lock:
        if group_id not in voice_rooms: return jsonify({'error': 'Pas de salon vocal.'}), 404
        if target not in voice_rooms[group_id]: return jsonify({'error': 'Pair introuvable.'}), 404
        peer = voice_rooms[group_id][target]
        if stype == 'offer':     peer['offers'][user['id']]     = data
        elif stype == 'answer':  peer['answers'][user['id']]    = data
        elif stype == 'candidate':
            if user['id'] not in peer['candidates']: peer['candidates'][user['id']] = []
            peer['candidates'][user['id']].append(data)
    return jsonify({'success': True})

@app.route('/api/voice/<int:group_id>/poll')
def voice_poll(group_id):
    """Get pending signals for me"""
    user, err = auth_check(request)
    if err: return err
    signals = []
    with voice_lock:
        if group_id in voice_rooms and user['id'] in voice_rooms[group_id]:
            me = voice_rooms[group_id][user['id']]
            for from_id, offer in list(me.get('offers', {}).items()):
                signals.append({'type': 'offer', 'from_id': from_id, 'data': offer})
                del me['offers'][from_id]
            for from_id, answer in list(me.get('answers', {}).items()):
                signals.append({'type': 'answer', 'from_id': from_id, 'data': answer})
                del me['answers'][from_id]
            for from_id, cands in list(me.get('candidates', {}).items()):
                for c in cands:
                    signals.append({'type': 'candidate', 'from_id': from_id, 'data': c})
                del me['candidates'][from_id]
    return jsonify({'signals': signals})

@app.route('/api/voice/<int:group_id>/mute', methods=['POST'])
def voice_mute_self(group_id):
    user, err = auth_check(request)
    if err: return err
    muted = (request.get_json() or {}).get('muted', True)
    with voice_lock:
        if group_id in voice_rooms and user['id'] in voice_rooms[group_id]:
            voice_rooms[group_id][user['id']]['muted'] = muted
    return jsonify({'success': True})

@app.route('/api/messages/save', methods=['POST'])
def save_message():
    user, err = auth_check(request)
    if err: return err
    d = request.get_json() or {}
    content     = (d.get('content') or '').strip()
    sender_name = (d.get('sender_name') or '').strip()
    if not content: return jsonify({'error': 'Message vide.'}), 400
    # Limite 50 messages sauvegardés par mois
    month_start = datetime.datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) as c FROM saved_messages WHERE user_id=%s AND saved_at>=%s', (user['id'], month_start))
            if cur.fetchone()['c'] >= 50:
                return jsonify({'error': 'Limite de 50 messages sauvegardés par mois atteinte.'}), 429
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
            cur.execute('INSERT INTO saved_messages (user_id, content, sender_name, expires_at) VALUES (%s,%s,%s,%s)',
                        (user['id'], content, sender_name, expires_at))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/messages/saved')
def get_saved_messages():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM saved_messages WHERE expires_at < %s', (datetime.datetime.utcnow(),))
            cur.execute('SELECT id, content, sender_name, saved_at FROM saved_messages WHERE user_id=%s ORDER BY saved_at DESC', (user['id'],))
            rows = cur.fetchall()
        conn.commit()
    return jsonify({'saved': [{'id': r['id'], 'content': r['content'], 'sender_name': r['sender_name'], 'saved_at': r['saved_at'].isoformat()} for r in rows]})

@app.route('/api/messages/saved/<int:msg_id>', methods=['DELETE'])
def delete_saved_message(msg_id):
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM saved_messages WHERE id=%s AND user_id=%s', (msg_id, user['id']))
        conn.commit()
    return jsonify({'success': True})

# ── Reçu / Vu ────────────────────────────────────────────────────────────────
@app.route('/api/messages/read', methods=['POST'])
def mark_read():
    user, err = auth_check(request)
    if err: return err
    d = request.get_json() or {}
    msg_ids = d.get('message_ids', [])
    if not msg_ids: return jsonify({'success': True})
    with get_db() as conn:
        with conn.cursor() as cur:
            for mid in msg_ids:
                cur.execute('''INSERT INTO message_reads (message_id, user_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING''', (mid, user['id']))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/messages/<int:other_id>/status')
def message_status(other_id):
    """Retourne les IDs des messages lus par l'autre personne"""
    user, err = auth_check(request)
    if err: return err
    since = request.args.get('since', 0)
    with get_db() as conn:
        with conn.cursor() as cur:
            # Messages envoyés par moi, lus par l'autre
            cur.execute('''
                SELECT m.id FROM messages m
                JOIN message_reads mr ON mr.message_id = m.id
                WHERE m.sender_id = %s AND m.receiver_id = %s
                AND mr.user_id = %s AND m.id > %s
            ''', (user['id'], other_id, other_id, since))
            read_ids = [r['id'] for r in cur.fetchall()]
            # Dernier message envoyé par moi (pour "envoyé")
            cur.execute('''SELECT MAX(id) as last_id FROM messages
                WHERE sender_id=%s AND receiver_id=%s AND group_id IS NULL''',
                (user['id'], other_id))
            row = cur.fetchone()
            last_sent_id = row['last_id'] if row else None
    return jsonify({'read_ids': read_ids, 'last_sent_id': last_sent_id})

# ── En train d'écrire ─────────────────────────────────────────────────────────
@app.route('/api/typing', methods=['POST'])
def set_typing():
    user, err = auth_check(request)
    if err: return err
    d         = request.get_json() or {}
    chat_with = d.get('chat_with')
    group_id  = d.get('group_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''INSERT INTO typing_status (user_id, chat_with, group_id, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    chat_with = EXCLUDED.chat_with,
                    group_id  = EXCLUDED.group_id,
                    updated_at = EXCLUDED.updated_at''',
                (user['id'], chat_with, group_id, datetime.datetime.utcnow()))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/typing/stop', methods=['POST'])
def stop_typing():
    user, err = auth_check(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM typing_status WHERE user_id=%s', (user['id'],))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/typing/<int:other_id>')
def get_typing(other_id):
    user, err = auth_check(request)
    if err: return err
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=4)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT u.username FROM typing_status ts
                JOIN users u ON u.id = ts.user_id
                WHERE ts.user_id = %s AND ts.chat_with = %s AND ts.updated_at > %s''',
                (other_id, user['id'], cutoff))
            row = cur.fetchone()
    return jsonify({'typing': row['username'] if row else None})

@app.route('/api/typing/group/<int:group_id>')
def get_group_typing(group_id):
    user, err = auth_check(request)
    if err: return err
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=4)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT u.username FROM typing_status ts
                JOIN users u ON u.id = ts.user_id
                WHERE ts.group_id = %s AND ts.user_id != %s AND ts.updated_at > %s''',
                (group_id, user['id'], cutoff))
            rows = cur.fetchall()
    return jsonify({'typing': [r['username'] for r in rows]})

@app.route('/api/status')
def api_status():
    return jsonify(server_state)

# ── Admin API ─────────────────────────────────────────────────────────────────
def require_admin(req):
    user, err = auth_check(req)
    if err: return None, err
    if not is_admin(user): return None, (jsonify({'error': 'Non autorisé.'}), 403)
    return user, None

@app.route('/api/admin/emergency', methods=['POST'])
def api_emergency():
    user, err = require_admin(request)
    if err: return err
    d = request.get_json() or {}
    server_state['status'] = 'emergency'
    server_state['emergency_message'] = d.get('message', server_state['emergency_message'])
    return jsonify({'success': True})

@app.route('/api/admin/pause', methods=['POST'])
def api_pause():
    user, err = require_admin(request)
    if err: return err
    server_state['status'] = 'paused'
    return jsonify({'success': True})

@app.route('/api/admin/resume', methods=['POST'])
def api_resume():
    user, err = require_admin(request)
    if err: return err
    server_state['status'] = 'open'
    return jsonify({'success': True})

@app.route('/api/admin/ban/<int:user_id>', methods=['POST'])
def api_ban(user_id):
    user, err = require_admin(request)
    if err: return err
    duration = int((request.get_json() or {}).get('duration', 10))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET banned_until=%s WHERE id=%s',
                        (datetime.datetime.utcnow() + datetime.timedelta(minutes=duration), user_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/admin/unban/<int:user_id>', methods=['POST'])
def api_unban(user_id):
    user, err = require_admin(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET banned_until=NULL WHERE id=%s', (user_id,))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/admin/users')
def api_admin_users():
    user, err = require_admin(request)
    if err: return err
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,username,email,verified,banned_until,created_at FROM users ORDER BY id DESC')
            rows = cur.fetchall()
            cur.execute('SELECT COUNT(*) as c FROM messages')
            msg_count = cur.fetchone()['c']
    users = [{'id': r['id'], 'username': r['username'], 'email': r['email'],
              'banned': bool(r['banned_until'] and datetime.datetime.utcnow() < r['banned_until']),
              'created_at': str(r['created_at'])[:10]} for r in rows]
    return jsonify({'users': users, 'msg_count': msg_count, 'server_status': server_state['status']})

# ── Dashboard Flask ───────────────────────────────────────────────────────────
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin1234')

ADMIN_CSS = """<style>
:root{--bg:#0e0c1a;--bg2:#16132a;--bg3:#1e1a35;--purple:#7c5cbf;--purple-l:#a07ee0;--border:#2e2850;--red:#c0392b;--red-dim:#7a1f16;--green:#27ae60;--amber:#d4a017;--text:#e8e3f0;--text-dim:#9b93b5;}
*{box-sizing:border-box;margin:0;padding:0;}body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;min-height:100vh;}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;justify-content:space-between;}
header h1{font-size:18px;font-weight:600;color:var(--purple-l);}header a{color:var(--text-dim);text-decoration:none;font-size:13px;}
.main{max-width:1100px;margin:0 auto;padding:32px 24px;}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px;}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px 24px;}
.stat-card .label{font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;}
.stat-card .value{font-size:32px;font-weight:700;color:var(--purple-l);}
.stat-card.status .value{font-size:18px;}.open{color:var(--green)!important;}.paused{color:var(--amber)!important;}.emergency{color:var(--red)!important;}
.section{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px;}
.section h2{font-size:14px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;}
.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;}form{display:inline;}
button{cursor:pointer;border:none;border-radius:8px;padding:10px 20px;font-size:13px;font-weight:600;font-family:inherit;transition:opacity .15s;}button:hover{opacity:.85;}
.btn-emergency{background:var(--red);color:#fff;}.btn-pause{background:var(--amber);color:#000;}.btn-resume{background:var(--green);color:#fff;}
.btn-danger{background:var(--red-dim);color:#f8a;border:1px solid var(--red);font-size:12px;padding:6px 12px;}
.btn-secondary{background:var(--bg3);color:var(--text);border:1px solid var(--border);font-size:12px;padding:6px 12px;}
.emergency-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.emergency-form input{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 14px;font-size:13px;width:280px;font-family:inherit;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:10px 14px;color:var(--text-dim);font-size:11px;text-transform:uppercase;border-bottom:1px solid var(--border);}
td{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:middle;}tr:last-child td{border-bottom:none;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-ok{background:#1a3d2e;color:#4ade80;}.badge-banned{background:#3d1515;color:#f87171;}
.ban-form{display:flex;gap:6px;align-items:center;}
.ban-form input[type=number]{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:5px 8px;width:56px;font-size:12px;font-family:inherit;}
.username-cell{font-weight:600;color:var(--purple-l);}.email-cell{color:var(--text-dim);}.date-cell{color:var(--text-dim);font-size:12px;}
.create-user-form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;}
.create-user-form div{display:flex;flex-direction:column;gap:4px;}
.create-user-form label{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.8px;}
.create-user-form input{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px 14px;font-size:13px;font-family:inherit;}
.create-user-form input:focus{outline:none;border-color:var(--purple);}
.btn-create{background:var(--purple);color:#fff;}
input[type=password]{width:100%;background:#0e0c1a;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:12px 14px;font-size:14px;font-family:inherit;margin-bottom:20px;}
input:focus{outline:none;border-color:var(--purple);}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:40px;width:360px;}
.auth-wrap{height:100vh;display:flex;align-items:center;justify-content:center;}
.error-box{background:#2d1515;border:1px solid var(--red);color:#f87171;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:20px;}
.success-box{background:#142d1e;border:1px solid #1a5e35;color:#4ade80;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:20px;}
label{display:block;font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;}
.btn-main{width:100%;background:var(--purple);color:#fff;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;}
</style>"""

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin'): return redirect('/admin/login')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,username,email,banned_until,created_at FROM users ORDER BY id DESC')
            users = cur.fetchall()
            cur.execute('SELECT COUNT(*) as c FROM messages'); msg_count = cur.fetchone()['c']
            cur.execute('SELECT COUNT(*) as c FROM users');    user_count = cur.fetchone()['c']
    st           = server_state['status']
    status_label = {'open':'Ouvert','paused':'En pause','emergency':"Arrêt d'urgence"}.get(st, st)
    error_msg    = request.args.get('error','')
    success_msg  = request.args.get('success','')
    flash = f'<div class="error-box">{error_msg}</div>' if error_msg else (f'<div class="success-box">{success_msg}</div>' if success_msg else '')
    rows = ''
    for u in users:
        banned  = u['banned_until'] and datetime.datetime.utcnow() < u['banned_until']
        badge   = '<span class="badge badge-banned">Banni</span>' if banned else '<span class="badge badge-ok">Actif</span>'
        ban_act = f'<form action="/admin/unban/{u["id"]}" method="post" style="display:inline"><button class="btn-secondary">Débannir</button></form>' if banned else f'<form action="/admin/ban/{u["id"]}" method="post" class="ban-form"><input type="number" name="duration" value="10" min="1" max="1440"><span style="font-size:11px;color:var(--text-dim)">min</span><button class="btn-danger">Bannir</button></form>'
        del_act = f'<form action="/admin/delete-user/{u["id"]}" method="post" style="display:inline" onsubmit="return confirm(\'Supprimer ?\')"><button class="btn-danger" style="margin-left:4px">Suppr.</button></form>'
        rows   += f'<tr><td class="date-cell">{u["id"]}</td><td class="username-cell">{u["username"]}</td><td class="email-cell">{u["email"]}</td><td>{badge}</td><td class="date-cell">{str(u["created_at"])[:10] if u["created_at"] else ""}</td><td style="display:flex;gap:4px;flex-wrap:wrap">{ban_act}{del_act}</td></tr>'
    resume_btn = '' if st=='open'      else '<form action="/admin/resume" method="post"><button class="btn-resume">Rouvrir</button></form>'
    pause_btn  = '' if st=='paused'    else '<form action="/admin/pause" method="post"><button class="btn-pause">Pause</button></form>'
    emerg_btn  = '' if st=='emergency' else f'<form action="/admin/emergency" method="post" class="emergency-form"><input type="text" name="message" placeholder="Message" value="{server_state["emergency_message"]}"><button class="btn-emergency">Urgence</button></form>'
    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Dashboard iChat</title>{ADMIN_CSS}</head><body>
<header><h1>Dashboard — iChat</h1><a href="/admin/logout">Déconnexion</a></header>
<div class="main">{flash}
<div class="stats">
  <div class="stat-card"><div class="label">Utilisateurs</div><div class="value">{user_count}</div></div>
  <div class="stat-card"><div class="label">Messages (24h)</div><div class="value">{msg_count}</div></div>
  <div class="stat-card status"><div class="label">Statut</div><div class="value {st}">{status_label}</div></div>
</div>
<div class="section"><h2>Contrôles serveur</h2><div class="controls">{resume_btn}{pause_btn}{emerg_btn}</div></div>
<div class="section"><h2>Créer un utilisateur</h2>
  <form action="/admin/create-user" method="post" class="create-user-form">
    <div><label>Pseudo</label><input type="text" name="username" placeholder="pseudo" required minlength="3"></div>
    <div><label>Email</label><input type="email" name="email" placeholder="email@exemple.com" required></div>
    <div><label>Mot de passe</label><input type="password" name="password" placeholder="min. 6 car." required minlength="6" style="width:auto;margin:0;padding:9px 14px;font-size:13px;border-radius:8px;"></div>
    <div style="padding-top:18px"><button class="btn-create" type="submit">Créer</button></div>
  </form>
</div>
<div class="section"><h2>Utilisateurs</h2>
<table><thead><tr><th>#</th><th>Pseudo</th><th>Email</th><th>Statut</th><th>Inscrit</th><th>Actions</th></tr></thead>
<tbody>{rows or '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-dim)">Aucun utilisateur</td></tr>'}</tbody></table>
</div></div></body></html>"""
    return Response(html, mimetype='text/html')

@app.route('/admin/create-user', methods=['POST'])
def admin_create_user():
    if not session.get('admin'): return 'Non autorisé', 403
    username = request.form.get('username','').strip()
    email    = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    if not all([username, email, password]): return redirect('/admin?error=Tous les champs sont requis.')
    if len(username) < 3: return redirect('/admin?error=Pseudo trop court.')
    if len(password) < 6: return redirect('/admin?error=Mot de passe trop court.')
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO users (username,email,password,verified) VALUES (%s,%s,%s,1)',
                            (username, email, generate_password_hash(password)))
            conn.commit()
        return redirect('/admin?success=Utilisateur créé !')
    except Exception:
        return redirect('/admin?error=Pseudo ou email déjà utilisé.')

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('admin'): return 'Non autorisé', 403
    with get_db() as conn:
        with conn.cursor() as cur:
            for q, p in [
                ('DELETE FROM tokens WHERE user_id=%s', (user_id,)),
                ('DELETE FROM messages WHERE sender_id=%s OR receiver_id=%s', (user_id, user_id)),
                ('DELETE FROM friends WHERE user_id=%s OR friend_id=%s', (user_id, user_id)),
                ('DELETE FROM group_members WHERE user_id=%s', (user_id,)),
                ('DELETE FROM users WHERE id=%s', (user_id,)),
            ]:
                cur.execute(q, p)
        conn.commit()
    return redirect('/admin')

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    error = ''
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True; return redirect('/admin')
        error = '<div class="error-box">Mot de passe incorrect.</div>'
    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Admin</title>{ADMIN_CSS}</head><body>
<div class="auth-wrap"><div class="card"><h1 style="font-size:20px;color:var(--purple-l);margin-bottom:8px">Dashboard Admin</h1>
<p style="color:var(--text-dim);font-size:13px;margin-bottom:24px">Accès réservé</p>
{error}<form method="post"><label>Mot de passe</label><input type="password" name="password" autofocus>
<button class="btn-main">Se connecter</button></form></div></div></body></html>"""
    return Response(html, mimetype='text/html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None); return redirect('/admin/login')

@app.route('/admin/emergency', methods=['POST'])
def admin_emergency():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'emergency'
    server_state['emergency_message'] = request.form.get('message', server_state['emergency_message'])
    return redirect('/admin')

@app.route('/admin/pause', methods=['POST'])
def admin_pause():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'paused'; return redirect('/admin')

@app.route('/admin/resume', methods=['POST'])
def admin_resume():
    if not session.get('admin'): return 'Non autorisé', 403
    server_state['status'] = 'open'; return redirect('/admin')

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
def admin_ban(user_id):
    if not session.get('admin'): return 'Non autorisé', 403
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET banned_until=%s WHERE id=%s',
                        (datetime.datetime.utcnow() + datetime.timedelta(minutes=int(request.form.get('duration',10))), user_id))
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

# ── Start ─────────────────────────────────────────────────────────────────────
try:
    init_db(); print('DB OK')
    threading.Thread(target=cleanup_loop, daemon=True).start(); print('Cleanup OK')
except Exception as e:
    print(f'Startup error: {e}')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
