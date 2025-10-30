"""
app.py - CodeConnect full backend (fixed + improved error handling)
"""

import os
import json
import logging
from datetime import datetime
import time

from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, flash, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError

from config import get_config

# -----------------------------------------------------------------------------
# App & extensions initialization
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(get_config())

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', manage_session=False)

# Ensure upload folder exists (UPLOAD_FOLDER should be defined in config.py)
os.makedirs(app.config.get('UPLOAD_FOLDER', 'static/uploads'), exist_ok=True)

# Setup logging
if not app.debug:
    # In production you might set a file handler; for now use basic config
    logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.DEBUG if app.debug else logging.INFO)

# Try to create tables if they are missing (safe in development)
try:
    with app.app_context():
        db.create_all()
        app.logger.debug("Database tables ensured/created.")
except Exception as e:
    app.logger.exception("Failed to create database tables on startup.")


# -----------------
# DATABASE MODELS
# -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, default="")
    avatar = db.Column(db.String(200))
    is_public = db.Column(db.Boolean, default=True)
    allow_dms_from = db.Column(db.String(20), default='everyone')
    follower_count = db.Column(db.Integer, default=0)
    following_count = db.Column(db.Integer, default=0)
    repo_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    public_key = db.Column(db.Text, nullable=True)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash.encode('utf-8'), password.encode('utf-8'))


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    follower = db.relationship('User', foreign_keys=[follower_id],
                              backref=db.backref('following_relations', lazy='dynamic', cascade='all, delete-orphan'))
    following = db.relationship('User', foreign_keys=[following_id],
                               backref=db.backref('follower_relations', lazy='dynamic', cascade='all, delete-orphan'))
    __table_args__ = (db.UniqueConstraint('follower_id', 'following_id', name='_follower_following_uc'),)


class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    language = db.Column(db.String(50))
    is_public = db.Column(db.Boolean, default=True)
    stars = db.Column(db.Integer, default=0)
    forks = db.Column(db.Integer, default=0)
    tags = db.Column(db.Text, default="[]")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('repositories', lazy='dynamic'))
    __table_args__ = (db.UniqueConstraint('owner_id', 'name', name='_owner_repo_uc'),)


class RepoFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    content_path = db.Column(db.String(255), nullable=False)
    encryption_metadata = db.Column(db.Text)
    language = db.Column(db.String(50))
    size = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    repository = db.relationship('Repository', backref=db.backref('files', lazy='dynamic', cascade='all, delete-orphan'))


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    participants = db.Column(db.Text, nullable=False)
    last_message_time = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    last_message = db.Column(db.Text)
    is_group = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    message_metadata = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    sender = db.relationship('User', backref='sent_messages')
    conversation = db.relationship('Conversation', backref=db.backref('messages', lazy='dynamic', order_by='Message.created_at'))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(20), default='text')
    repo_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=True)
    code_snippet = db.Column(db.Text)
    likes = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    author = db.relationship('User', backref='posts')
    repository = db.relationship('Repository')


class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('post_id', 'user_id', name='_post_user_uc'),)


class RepoStar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    repo_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('repo_id', 'user_id', name='_repo_user_uc'),)


class PostComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    author = db.relationship('User')
    post = db.relationship('Post', backref=db.backref('comment_objects', lazy='dynamic', cascade='all, delete-orphan'))


# -----------------
# HELPERS
# -----------------
def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return db.session.get(User, user_id)
    return None


def can_message_user(sender, recipient):
    if not sender or not recipient:
        return False
    if sender.id == recipient.id:
        return False
    if recipient.allow_dms_from == 'everyone':
        return True
    elif recipient.allow_dms_from == 'followers':
        return Follow.query.filter_by(follower_id=recipient.id, following_id=sender.id).count() > 0
    return False


def allowed_file(filename):
    # Default allowed extensions include common image types for avatars
    allowed = app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif', 'webp'})
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


# -----------------
# ROUTES
# -----------------
@app.route('/api/csrf_token')
def get_csrf_token():
    # Return a CSRF token if user is logged in — otherwise still provide a token for forms
    try:
        token = generate_csrf()
        return jsonify({'csrf_token': token})
    except Exception:
        # Fallback
        return jsonify({'csrf_token': ''})


@csrf.exempt
@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Robustly parse incoming data: prefer JSON but fall back to form-data.
        content_type = request.headers.get('Content-Type', '')
        app.logger.info(f"Login POST Content-Type: {content_type}")

        raw_body = request.get_data(as_text=True)
        app.logger.info(f"Login POST raw body (first 500 chars): {raw_body[:500]}")

        data = {}
        if raw_body:
            # Try parse JSON even if content-type isn't exactly JSON
            try:
                data = json.loads(raw_body)
                app.logger.debug('Parsed JSON body for login')
            except Exception:
                app.logger.debug('Failed to parse JSON body for login; falling back to form')
                data = request.form.to_dict()
        else:
            data = request.form.to_dict()
        username_or_email = data.get('username')
        password = data.get('password')

        if not username_or_email or not password:
            return jsonify({'success': False, 'message': 'Username/Email and password required'}), 400

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session.permanent = True
            return jsonify({'success': True, 'redirect': url_for('index')})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    return render_template('login.html')


# Allow registration without CSRF token (frontend posts JSON on signup)
@csrf.exempt
@app.route('/register', methods=['POST'])
def register():
    """User registration - public_key optional"""
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()
        required_fields = ['username', 'email', 'password', 'display_name']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'success': False, 'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        username = data.get('username').strip()
        email = data.get('email').strip()
        password = data.get('password')
        display_name = data.get('display_name').strip()
        public_key = data.get('public_key')  # optional

        if len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400

        # Ensure email/username uniqueness using try/except around commit to catch race conditions
        user = User(username=username, email=email, display_name=display_name, public_key=public_key or None)
        user.set_password(password)

        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError as ie:
            db.session.rollback()
            # Determine which unique constraint failed
            if User.query.filter_by(username=username).first():
                return jsonify({'success': False, 'message': 'Username already exists'}), 409
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'}), 409
            # Generic
            app.logger.exception("IntegrityError during registration")
            return jsonify({'success': False, 'message': 'Registration failed due to database integrity error.'}), 500

        session['user_id'] = user.id
        session.permanent = True
        app.logger.info(f"New user registered: {username}")

        return jsonify({'success': True, 'redirect': url_for('index')}), 201

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Registration failed")
        # In debug mode provide the exception message to the client for easier debugging.
        if app.debug:
            return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500
        return jsonify({'success': False, 'message': 'Registration failed due to server error. Please try again later.'}), 500


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    followed_ids = [f.following_id for f in user.following_relations]
    feed_ids = followed_ids + [user.id]

    posts_query = db.session.query(Post, User).join(User, Post.author_id == User.id)
    posts_data = posts_query.filter(Post.author_id.in_(feed_ids)).order_by(Post.created_at.desc()).limit(30).all()

    liked_post_ids = set()
    if user:
        likes = PostLike.query.filter(PostLike.user_id == user.id, PostLike.post_id.in_([p.id for p, a in posts_data])).all()
        liked_post_ids = {like.post_id for like in likes}

    default_avatar = url_for('static', filename='images/default_avatar.png')

    feed_posts = []
    for post, author in posts_data:
        post_dict = {
            'id': post.id,
            'content': post.content,
            'post_type': post.post_type,
            'likes': post.likes or 0,
            'is_liked_by_user': post.id in liked_post_ids,
            'comments': post.comments or 0,
            'created_at': post.created_at.strftime('%Y-%m-%d %H:%M'),
            'author': {
                'username': author.username,
                'display_name': author.display_name,
                'avatar': author.avatar or default_avatar
            }
        }
        if post.code_snippet:
            try:
                post_dict['code_snippet'] = json.loads(post.code_snippet)
            except (json.JSONDecodeError, TypeError):
                post_dict['code_snippet'] = None
        if post.repo_id and post.repository:
            post_dict['repository'] = {
                'name': post.repository.name,
                'description': post.repository.description,
                'language': post.repository.language,
                'owner_username': post.repository.owner.username
            }
        feed_posts.append(post_dict)

    return render_template('dashboard.html', user=user, posts=feed_posts)


@app.route('/profile/<username>')
def profile(username):
    user = get_current_user()
    profile_user = User.query.filter_by(username=username).first_or_404()

    if not profile_user.is_public and (not user or user.id != profile_user.id):
        abort(403, description="Profile is private")

    repos_query = Repository.query.filter_by(owner_id=profile_user.id)
    if not user or user.id != profile_user.id:
        repos_query = repos_query.filter_by(is_public=True)
    repos = repos_query.order_by(Repository.updated_at.desc()).all()

    is_following = False
    if user and user.id != profile_user.id:
        is_following = db.session.query(Follow.id).filter_by(follower_id=user.id, following_id=profile_user.id).first() is not None

    return render_template('profile.html', user=user, profile_user=profile_user, repositories=repos, is_following=is_following)


@app.route('/repositories')
def repositories():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    repos = user.repositories.order_by(Repository.updated_at.desc()).all()
    return render_template('repositories.html', user=user, repositories=repos)


@app.route('/repo/<username>/<repo_name>')
def view_repository(username, repo_name):
    user = get_current_user()
    owner = User.query.filter_by(username=username).first_or_404()
    repo = Repository.query.filter_by(owner_id=owner.id, name=repo_name).first_or_404()

    if not repo.is_public and (not user or user.id != owner.id):
        abort(403, description="Repository is private")

    files = repo.files.order_by(RepoFile.filename).all()

    is_starred = False
    if user:
        is_starred = db.session.query(RepoStar.id).filter_by(repo_id=repo.id, user_id=user.id).first() is not None

    return render_template('repository.html', user=user, repository=repo, owner=owner, files=files, is_starred=is_starred)


@app.route('/messages')
def messages():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    # Find conversations where this user is a participant.
    user_id_str = f'"{user.id}"'
    conversations = Conversation.query.filter(Conversation.participants.like(f'%{user_id_str}%')).order_by(Conversation.last_message_time.desc()).all()

    conv_list = []
    default_avatar = url_for('static', filename='images/default_avatar.png')

    for conv in conversations:
        try:
            participants = json.loads(conv.participants)
            # handle 2-person conversations: pick the other user
            other_user_id = next((p_id for p_id in participants if p_id != user.id), None)
            if other_user_id:
                other_user = db.session.get(User, other_user_id)
                if other_user:
                    # Create a stable client-side conversation identifier that matches the client's conv_<min>_<max> scheme
                    try:
                        ids_sorted = sorted([int(x) for x in participants])
                        client_conv_id = f"conv_{ids_sorted[0]}_{ids_sorted[1]}" if len(ids_sorted) >= 2 else f"conv_{conv.id}"
                    except Exception:
                        client_conv_id = f"conv_{conv.id}"

                    conv_list.append({
                        'db_id': conv.id,
                        'conv_id': client_conv_id,
                        'name': conv.name or other_user.display_name,
                        'last_message': conv.last_message or '',
                        'last_message_time': conv.last_message_time.strftime('%H:%M') if conv.last_message_time else '',
                        'other_user': {
                            'id': other_user.id,
                            'username': other_user.username,
                            'display_name': other_user.display_name,
                            'avatar': other_user.avatar or default_avatar
                        }
                    })
        except (json.JSONDecodeError, StopIteration, TypeError):
            app.logger.warning(f"Skipping malformed conversation {conv.id}")
            continue

    return render_template('messages.html', user=user, conversations=conv_list)


@app.route('/api/user/<username>/public_key')
def get_user_public_key_api(username):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    target_user = User.query.filter_by(username=username).first()
    if target_user and target_user.public_key:
        return jsonify({"username": target_user.username, "public_key": target_user.public_key})
    elif target_user:
        return jsonify({"error": "User has not uploaded a public key"}), 404
    else:
        return jsonify({"error": "User not found"}), 404


@app.route('/api/start_conversation/<username>', methods=['POST'])
def start_conversation_api(username):
    """Create or return a conversation between the current user and <username>.

    Returns JSON with client-friendly conv id (conv_min_max) and the DB id.
    """
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    if target.id == user.id:
        return jsonify({'success': False, 'message': 'Cannot start a conversation with yourself'}), 400

    try:
        ids = sorted([int(user.id), int(target.id)])
        participants_json = json.dumps(ids)
        conversation = Conversation.query.filter_by(participants=participants_json, is_group=False).first()
        if not conversation:
            conversation = Conversation(participants=participants_json, last_message='', is_group=False)
            db.session.add(conversation)
            db.session.commit()

        client_conv_id = f"conv_{ids[0]}_{ids[1]}"
        return jsonify({
            'success': True,
            'client_conv_id': client_conv_id,
            'conversation_id': conversation.id,
            'other_user': {
                'id': target.id,
                'username': target.username,
                'display_name': target.display_name,
                'avatar': target.avatar or url_for('static', filename='images/default_avatar.png')
            }
        })
    except Exception as e:
        app.logger.exception(f"Failed to create/return conversation: {e}")
        return jsonify({'success': False, 'message': 'Could not start conversation'}), 500


@app.route('/api/search_users')
def search_users_api():
    """Search users by username or display name. Returns a small list of matches.

    Query string: ?q=<term>
    """
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'success': True, 'results': []})

    try:
        pattern = f"%{q}%"
        matches = User.query.filter(
            (User.username.ilike(pattern)) | (User.display_name.ilike(pattern)),
            User.id != user.id
        ).limit(8).all()

        results = []
        for u in matches:
            results.append({
                'id': u.id,
                'username': u.username,
                'display_name': u.display_name,
                'avatar': u.avatar or url_for('static', filename='images/default_avatar.png')
            })

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        app.logger.exception(f"Search users failed: {e}")
        return jsonify({'success': False, 'message': 'Search failed'}), 500


# -----------------
# SOCKET.IO HANDLERS
# -----------------
online_users = {}

@socketio.on('connect')
def on_connect():
    user = get_current_user()
    if user:
        join_room(f"user_{user.id}")
        online_users[user.id] = request.sid
        app.logger.debug(f"User {user.username} connected (ID: {user.id})")
    else:
        # Allow unauthenticated socket connections so the client can complete the
        # WebSocket handshake and then announce the authenticated user via
        # the 'user_online_announce' event. Returning False here rejects the
        # connection during the handshake which prevents the client from
        # emitting the announcement.
        app.logger.debug("Unauthenticated socket connected; waiting for announcement.")

    # Always accept the connection (no explicit False return)
    app.logger.debug(f"Socket connected: sid={request.sid}")


@socketio.on('disconnect')
def on_disconnect():
    disconnected_user_id = None
    for uid, sid in list(online_users.items()):
        if sid == request.sid:
            disconnected_user_id = uid
            del online_users[uid]
            break
    if disconnected_user_id:
        app.logger.debug(f"User ID {disconnected_user_id} disconnected")


@socketio.on('user_online_announce')
def handle_user_online_announce():
    # Allow an optional payload (e.g., {"user_id": 123}) from the client to
    # register the socket if the Flask session isn't available in the socket
    # context. Prefer the server-side session when present.
    try:
        user = get_current_user()
        if user:
            online_users[user.id] = request.sid
            app.logger.debug(f"User {user.username} marked online")
            return

        # Try to inspect the raw request JSON for a user_id (client may supply it)
        data = None
        try:
            data = request.get_json(force=False, silent=True)
        except Exception:
            data = None

        if data and 'user_id' in data:
            try:
                uid = int(data.get('user_id'))
                target_user = db.session.get(User, uid)
                if target_user:
                    online_users[uid] = request.sid
                    app.logger.debug(f"User (by id) {target_user.username} marked online via announcement")
                    return
            except Exception:
                app.logger.debug("Invalid user_id in user_online_announce payload")

        app.logger.debug("user_online_announce received but no authenticated user found")
    except Exception:
        app.logger.exception("Error handling user_online_announce")


@socketio.on('join_conversation')
def on_join_conversation(data):
    user = get_current_user()
    if not user:
        return
    conversation_id = data.get('conversation_id')
    if not conversation_id:
        return
    room_name = f"conv_{conversation_id}"
    join_room(room_name)
    app.logger.debug(f"{user.username} joined {room_name}")
    emit('status', {'msg': f'You joined conversation {conversation_id}.', 'conv_id': conversation_id})


@socketio.on('leave_conversation')
def on_leave_conversation(data):
    user = get_current_user()
    if not user:
        return
    conversation_id = data.get('conversation_id')
    if conversation_id:
        room_name = f"conv_{conversation_id}"
        leave_room(room_name)
        app.logger.debug(f"{user.username} left {room_name}")


# Replace the on_send_message function in app.py with this fixed version

@socketio.on('send_message')
def on_send_message(data):
    sender = get_current_user()
    if not sender:
        return emit('error', {'message': 'Authentication required'})

    conversation_id_str = data.get('conversation_id')
    encrypted_content = data.get('content')
    message_type = data.get('message_type', 'text')
    metadata = data.get('metadata', {})

    # CRITICAL: Log what we received from client
    app.logger.debug(f"Received message from {sender.username}:")
    app.logger.debug(f"  - conversation_id: {conversation_id_str}")
    app.logger.debug(f"  - content length: {len(encrypted_content) if encrypted_content else 0}")
    app.logger.debug(f"  - metadata: {metadata}")
    app.logger.debug(f"  - metadata.iv present: {'iv' in metadata}")
    app.logger.debug(f"  - metadata.iv length: {len(metadata.get('iv', '')) if metadata.get('iv') else 0}")

    if not conversation_id_str or not encrypted_content:
        return emit('error', {'message': 'Missing conversation ID or content'})

    # CRITICAL FIX: Validate that IV is present in metadata
    if not metadata or 'iv' not in metadata or not metadata['iv']:
        app.logger.error(f"Message from {sender.username} missing IV in metadata!")
        return emit('error', {'message': 'Missing encryption IV in metadata'})

    try:
        user_ids_str = conversation_id_str.split('_')[1:]
        user_ids = [int(uid) for uid in user_ids_str]
        if sender.id not in user_ids:
            return emit('error', {'message': 'Not authorized for this conversation'})

        recipient_id = next((uid for uid in user_ids if uid != sender.id), None)
        if not recipient_id:
            return emit('error', {'message': 'Recipient not found'})

        recipient = db.session.get(User, recipient_id)
        if not recipient or not can_message_user(sender, recipient):
            return emit('error', {'message': 'You cannot message this user'})

        participants_json = json.dumps(sorted(user_ids))
        conversation = Conversation.query.filter_by(participants=participants_json, is_group=False).first()
        if not conversation:
            conversation = Conversation(participants=participants_json, last_message="Message")
            db.session.add(conversation)
            db.session.commit()

    except Exception as e:
        app.logger.exception(f"Error finding/creating conversation: {e}")
        return emit('error', {'message': 'Invalid conversation ID format'})

    try:
        # Store the message with metadata as JSON string
        message = Message(
            conversation_id=conversation.id,
            sender_id=sender.id,
            content=encrypted_content,
            message_type=message_type,
            message_metadata=json.dumps(metadata)  # Store as JSON
        )
        db.session.add(message)

        conversation.last_message = f"{message_type.capitalize()} message"
        conversation.last_message_time = datetime.utcnow()
        db.session.commit()

        # CRITICAL FIX: Ensure metadata is properly included in emit
        emit_data = {
            'id': message.id,
            'conversation_id': conversation_id_str,
            'real_conv_id': conversation.id,
            'content': encrypted_content,
            'message_type': message_type,
            'metadata': metadata,  # Pass metadata as-is (dict with iv)
            'sender': {
                'id': sender.id,
                'username': sender.username,
                'display_name': sender.display_name,
                'avatar': sender.avatar
            },
            'created_at': message.created_at.isoformat() + 'Z'
        }

        # Log what we're about to emit
        app.logger.debug(f"Emitting message {message.id}:")
        app.logger.debug(f"  - To user rooms: {user_ids}")
        app.logger.debug(f"  - metadata.iv length: {len(emit_data['metadata'].get('iv', ''))}")

        # Emit to all participants
        for user_id in user_ids:
            user_room = f"user_{user_id}"
            emit('new_message', emit_data, room=user_room)
            app.logger.debug(f"  - Emitted to {user_room}")

        app.logger.info(f"Message {message.id} sent successfully from {sender.username} to conversation {conversation_id_str}")

    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Failed to send message: {e}")
        emit('error', {'message': 'Failed to send message'})

    try:
        message = Message(
            conversation_id=conversation.id,
            sender_id=sender.id,
            content=encrypted_content,
            message_type=message_type,
            message_metadata=json.dumps(metadata)
        )
        db.session.add(message)

        conversation.last_message = f"{message_type.capitalize()} message"
        conversation.last_message_time = datetime.utcnow()
        db.session.commit()

        emit_data = {
            'id': message.id,
            'conversation_id': conversation_id_str,
            'real_conv_id': conversation.id,
            'content': encrypted_content,
            'message_type': message_type,
            'metadata': metadata,
            'sender': {
                'id': sender.id,
                'username': sender.username,
                'display_name': sender.display_name
            },
            'created_at': message.created_at.isoformat() + 'Z'
        }

        for user_id in user_ids:
            user_room = f"user_{user_id}"
            emit('new_message', emit_data, room=user_room)
            app.logger.debug(f"Message {message.id} → {user_room}")

    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Failed to send message: {e}")
        emit('error', {'message': 'Failed to send message'})


@socketio.on('key_established')
def on_key_established(data):
    """
    Relay acknowledgement that a recipient successfully imported/decrypted
    a session key so the original sender can safely start sending encrypted messages.
    """
    user = get_current_user()
    if not user:
        return emit('error', {'message': 'Authentication required'})

    target_id = data.get('other_user_id')
    if not target_id:
        return

    target_sid = online_users.get(target_id)
    if target_sid:
        emit('key_established', {
            'other_user_id': user.id,
            'other_username': user.username
        }, room=target_sid)
    else:
        app.logger.info(f"Could not forward key_established to {target_id} (offline)")

@socketio.on('exchange_keys')
def exchange_keys(data):
    sender = get_current_user()
    if not sender:
        return emit('error', {'message': 'Authentication required'})

    recipient_id = data.get('recipient_id')
    encrypted_key = data.get('encrypted_key')

    if not recipient_id or not encrypted_key:
        return emit('error', {'message': 'Missing recipient ID or key data'})

    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        recipient_user = db.session.get(User, recipient_id)
        recipient_username = recipient_user.username if recipient_user else f"ID {recipient_id}"
        app.logger.debug(f"Key exchange: {sender.username} → {recipient_username}")
        emit('key_exchange', {
            'sender_id': sender.id,
            'sender_username': sender.username,
            'encrypted_key': encrypted_key
        }, room=recipient_sid)
    else:
        recipient_user = db.session.get(User, recipient_id)
        recipient_username = recipient_user.username if recipient_user else f"ID {recipient_id}"
        app.logger.debug(f"Cannot relay key: {recipient_username} not online")
        emit('error', {'message': f'User {recipient_username} is not online.'})


# -----------------
# API: Follow/Like/Post/Repo endpoints (same as original)
# -----------------
@app.route('/api/follow/<username>', methods=['POST'])
@csrf.exempt
def follow_user_api(username):
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    if target_user.id == user.id:
        return jsonify({'success': False, 'message': 'Cannot follow yourself'}), 400

    if Follow.query.filter_by(follower_id=user.id, following_id=target_user.id).first():
        return jsonify({'success': False, 'message': 'Already following'}), 409

    try:
        follow = Follow(follower_id=user.id, following_id=target_user.id)
        db.session.add(follow)
        user.following_count = (user.following_count or 0) + 1
        target_user.follower_count = (target_user.follower_count or 0) + 1
        db.session.commit()
        return jsonify({'success': True, 'follower_count': target_user.follower_count})
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Follow failed: {e}")
        return jsonify({'success': False, 'message': 'Could not follow user'}), 500


@app.route('/api/unfollow/<username>', methods=['POST'])
@csrf.exempt
def unfollow_user_api(username):
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    follow = Follow.query.filter_by(follower_id=user.id, following_id=target_user.id).first()
    if not follow:
        return jsonify({'success': False, 'message': 'Not following'}), 404

    try:
        db.session.delete(follow)
        user.following_count = max(0, (user.following_count or 1) - 1)
        target_user.follower_count = max(0, (target_user.follower_count or 1) - 1)
        db.session.commit()
        return jsonify({'success': True, 'follower_count': target_user.follower_count})
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Unfollow failed: {e}")
        return jsonify({'success': False, 'message': 'Could not unfollow user'}), 500


@app.route('/api/like_post/<int:post_id>', methods=['POST'])
@csrf.exempt
def like_post_api(post_id):
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found'}), 404

    existing_like = PostLike.query.filter_by(post_id=post_id, user_id=user.id).first()

    try:
        if existing_like:
            db.session.delete(existing_like)
            post.likes = max(0, (post.likes or 1) - 1)
            liked = False
        else:
            like = PostLike(post_id=post_id, user_id=user.id)
            db.session.add(like)
            post.likes = (post.likes or 0) + 1
            liked = True

        db.session.commit()
        return jsonify({'success': True, 'liked': liked, 'likes': post.likes})
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Like/unlike failed: {e}")
        return jsonify({'success': False, 'message': 'Could not update like'}), 500


@app.route('/api/post/<int:post_id>/comments', methods=['GET', 'POST'])
@csrf.exempt
def post_comments_api(post_id):
    user = get_current_user()
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({'success': False, 'message': 'Post not found'}), 404

    if request.method == 'GET':
        comments = PostComment.query.filter_by(post_id=post_id).order_by(PostComment.created_at.asc()).all()
        results = []
        for c in comments:
            results.append({
                'id': c.id,
                'author': {
                    'id': c.author.id,
                    'username': c.author.username,
                    'display_name': c.author.display_name,
                },
                'content': c.content,
                'created_at': c.created_at.isoformat() + 'Z'
            })
        return jsonify({'success': True, 'comments': results})

    # POST: create comment
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400
    data = request.get_json()
    content = data.get('content')
    if not content or not content.strip():
        return jsonify({'success': False, 'message': 'Comment content required'}), 400

    try:
        comment = PostComment(post_id=post_id, author_id=user.id, content=content.strip())
        db.session.add(comment)
        post.comments = (post.comments or 0) + 1
        db.session.commit()
        return jsonify({'success': True, 'comment_id': comment.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Failed to create comment: {e}")
        return jsonify({'success': False, 'message': 'Could not create comment'}), 500


@app.route('/api/create_post', methods=['POST'])
@csrf.exempt
def create_post_api():
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    if not request.is_json:
        return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'success': False, 'message': 'Post content required'}), 400

    post_type = data.get('post_type', 'text')
    repo_id = data.get('repo_id')
    code_snippet_data = data.get('code_snippet')

    try:
        post = Post(author_id=user.id, content=content, post_type=post_type)

        if post_type == 'repo_share' and repo_id:
            repo = db.session.get(Repository, repo_id)
            if repo and (repo.is_public or repo.owner_id == user.id):
                post.repo_id = repo_id
            else:
                return jsonify({'success': False, 'message': 'Invalid repository'}), 400

        elif post_type == 'code_snippet' and code_snippet_data:
            if isinstance(code_snippet_data, dict) and 'code' in code_snippet_data:
                post.code_snippet = json.dumps(code_snippet_data)
            else:
                return jsonify({'success': False, 'message': 'Invalid code snippet'}), 400

        db.session.add(post)
        db.session.commit()
        return jsonify({'success': True, 'post_id': post.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Post creation failed: {e}")
        return jsonify({'success': False, 'message': 'Could not create post'}), 500


@app.route('/api/create_repo', methods=['POST'])
@csrf.exempt
def create_repository_api():
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    if not request.is_json:
        return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'success': False, 'message': 'Repository name is required'}), 400

    safe_name = secure_filename(name).replace('_', '-')
    if not safe_name or safe_name != name:
        return jsonify({'success': False, 'message': 'Invalid repository name'}), 400

    if Repository.query.filter_by(owner_id=user.id, name=safe_name).first():
        return jsonify({'success': False, 'message': 'Repository name already exists'}), 409

    try:
        repo = Repository(
            owner_id=user.id,
            name=safe_name,
            description=data.get('description', ''),
            language=data.get('language', ''),
            is_public=data.get('is_public', True),
            tags=json.dumps(data.get('tags', []))
        )
        db.session.add(repo)
        user.repo_count = (user.repo_count or 0) + 1
        db.session.commit()
        return jsonify({'success': True, 'repo_id': repo.id, 'name': repo.name}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Repo creation failed: {e}")
        return jsonify({'success': False, 'message': 'Could not create repository'}), 500


@app.route('/api/star_repo/<int:repo_id>', methods=['POST'])
@csrf.exempt
def star_repository_api(repo_id):
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    repo = db.session.get(Repository, repo_id)
    if not repo:
        return jsonify({'success': False, 'message': 'Repository not found'}), 404

    existing_star = RepoStar.query.filter_by(repo_id=repo_id, user_id=user.id).first()

    try:
        if existing_star:
            db.session.delete(existing_star)
            repo.stars = max(0, (repo.stars or 1) - 1)
            starred = False
        else:
            star = RepoStar(repo_id=repo_id, user_id=user.id)
            db.session.add(star)
            repo.stars = (repo.stars or 0) + 1
            starred = True

        db.session.commit()
        return jsonify({'success': True, 'starred': starred, 'stars': repo.stars})
    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Star/unstar failed: {e}")
        return jsonify({'success': False, 'message': 'Could not update star status'}), 500


@app.route('/api/update_profile', methods=['POST'])
@csrf.exempt
def update_profile_api():
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    # Accept form-data (for avatar upload) or JSON
    try:
        display_name = request.form.get('display_name') or request.json.get('display_name') if request.is_json else request.form.get('display_name')
        bio = request.form.get('bio') or (request.json.get('bio') if request.is_json else request.form.get('bio'))
        allow_dms_from = request.form.get('allow_dms_from') or (request.json.get('allow_dms_from') if request.is_json else request.form.get('allow_dms_from'))

        # Update simple fields
        if display_name:
            user.display_name = display_name.strip()
        user.bio = bio or ''
        if allow_dms_from in ('everyone', 'followers', 'none'):
            user.allow_dms_from = allow_dms_from

        # Handle avatar upload
        if 'avatar' in request.files:
            avatar_file = request.files['avatar']
            if avatar_file and allowed_file(avatar_file.filename):
                orig_filename = secure_filename(avatar_file.filename)
                # Create a unique filename to avoid collisions
                unique_name = f"{user.id}_{int(time.time())}_{orig_filename}"
                upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')
                # Ensure upload folder exists relative to app root
                upload_dir = upload_folder
                if not os.path.isabs(upload_dir):
                    upload_dir = os.path.join(app.root_path, upload_folder)
                os.makedirs(upload_dir, exist_ok=True)
                save_path = os.path.join(upload_dir, unique_name)
                avatar_file.save(save_path)
                # Build a static URL relative to the 'static' folder
                static_dir = os.path.join(app.root_path, 'static')
                rel_path = os.path.relpath(save_path, static_dir).replace('\\', '/')
                user.avatar = url_for('static', filename=rel_path)

        # Handle public key - can be provided as textarea in form or JSON
        public_key = request.form.get('public_key') or (request.json.get('public_key') if request.is_json else None)
        if public_key:
            user.public_key = public_key.strip() or None

        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated'})

    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Profile update failed: {e}")
        return jsonify({'success': False, 'message': 'Could not update profile'}), 500


@app.route('/repo/<username>/<repo_name>/file/<int:file_id>')
def view_file(username, repo_name, file_id):
    user = get_current_user()
    owner = User.query.filter_by(username=username).first_or_404()
    repo = Repository.query.filter_by(owner_id=owner.id, name=repo_name).first_or_404()
    repo_file = RepoFile.query.filter_by(id=file_id, repo_id=repo.id).first_or_404()

    if not repo.is_public and (not user or user.id != owner.id):
        abort(403, description="Repository is private")

    try:
        with open(repo_file.content_path, 'r', encoding='utf-8') as f:
            content = f.read()
            return render_template('file_view.html', 
                user=user, 
                repository=repo, 
                owner=owner, 
                file=repo_file, 
                content=content)
    except Exception as e:
        app.logger.error(f"Error reading file {repo_file.content_path}: {str(e)}")
        abort(500, description="Could not read file contents")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return (render_template('404.html'), 404) if os.path.exists('templates/404.html') else ('Not Found', 404)


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return (render_template('500.html'), 500) if os.path.exists('templates/500.html') else ('Internal Server Error', 500)
