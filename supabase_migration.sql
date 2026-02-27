-- Supabase Migration Script for Firewall System
-- Run this SQL in your Supabase SQL Editor to create the required tables

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security logs table
CREATE TABLE IF NOT EXISTS security_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp DOUBLE PRECISION NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    size INTEGER NOT NULL,
    description TEXT,
    user_identity TEXT,
    user_device TEXT,
    user_resource TEXT,
    ai_score DOUBLE PRECISION,
    decision TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Network traffic stats table
CREATE TABLE IF NOT EXISTS network_stats (
    id BIGSERIAL PRIMARY KEY,
    timestamp DOUBLE PRECISION NOT NULL,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    allowed_count INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    quarantined_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp ON security_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_severity ON security_logs(severity);
CREATE INDEX IF NOT EXISTS idx_security_logs_decision ON security_logs(decision);
CREATE INDEX IF NOT EXISTS idx_security_logs_protocol ON security_logs(protocol);
CREATE INDEX IF NOT EXISTS idx_network_stats_timestamp ON network_stats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

