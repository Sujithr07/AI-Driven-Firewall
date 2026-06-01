"""Authentication and user-management endpoints."""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

from db.client import supabase

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Check if user exists
        username_result = supabase.table('users').select('*').eq('username', username).execute()
        email_result = supabase.table('users').select('*').eq('email', email).execute()

        if username_result.data or email_result.data:
            return jsonify({'error': 'User already exists'}), 400

        # Create user
        password_hash = generate_password_hash(password)
        supabase.table('users').insert({
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': 'user'
        }).execute()

        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'error': 'Failed to create user'}), 500


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Login and get JWT token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    try:
        result = supabase.table('users').select('*').eq('username', username).execute()

        if not result.data or len(result.data) == 0:
            return jsonify({'error': 'Invalid credentials'}), 401

        user = result.data[0]

        if not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Create access token
        access_token = create_access_token(identity=username)

        return jsonify({
            'access_token': access_token,
            'user': {
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    username = get_jwt_identity()

    try:
        result = supabase.table('users').select('username, email, role').eq('username', username).execute()

        if not result.data or len(result.data) == 0:
            return jsonify({'error': 'User not found'}), 404

        user = result.data[0]

        return jsonify({
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }), 200
    except Exception as e:
        print(f"Error in get_current_user: {e}")
        return jsonify({'error': 'Failed to get user info'}), 500


@auth_bp.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    """Get all users (admin only)"""
    username = get_jwt_identity()

    try:
        result = supabase.table('users').select('role').eq('username', username).execute()

        if not result.data or len(result.data) == 0 or result.data[0]['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403

        users_result = supabase.table('users').select('id, username, email, role, created_at').execute()
        users = users_result.data

        return jsonify({'users': users})
    except Exception as e:
        print(f"Error in get_users: {e}")
        return jsonify({'error': 'Failed to get users'}), 500
