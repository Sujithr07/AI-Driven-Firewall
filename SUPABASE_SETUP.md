# Supabase Setup Guide

This guide will help you set up Supabase for the Firewall System application.

## Prerequisites

1. A Supabase account (sign up at https://supabase.com)
2. A new Supabase project

## Setup Steps

### 1. Create a Supabase Project

1. Go to https://supabase.com and sign in
2. Click "New Project"
3. Fill in your project details:
   - Name: `firewall-system` (or any name you prefer)
   - Database Password: Choose a strong password (save this!)
   - Region: Choose the closest region to you
4. Wait for the project to be created (takes a few minutes)

### 2. Create Database Tables

1. In your Supabase project dashboard, go to the "SQL Editor"
2. Open the file `supabase_migration.sql` from this project
3. Copy and paste the entire SQL script into the SQL Editor
4. Click "Run" to execute the migration
5. Verify that the tables were created by going to "Table Editor" - you should see:
   - `users`
   - `security_logs`
   - `network_stats`

### 3. Get Your Supabase Credentials

1. In your Supabase project dashboard, go to "Settings" → "API"
2. You'll need two values:
   - **Project URL**: Found under "Project URL"
   - **anon/public key**: Found under "Project API keys" → "anon public"

### 4. Configure Environment Variables

1. Create a `.env` file in the project root (if it doesn't exist)
2. Add the following lines:

```
SUPABASE_URL=your_project_url_here
SUPABASE_KEY=your_anon_key_here
```

Replace `your_project_url_here` with your Project URL and `your_anon_key_here` with your anon public key.

Example:
```
SUPABASE_URL=https://abcdefghijklmnop.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTYxNjIzOTAyMiwiZXhwIjoxOTMxODE1MDIyfQ.abcdefghijklmnopqrstuvwxyz1234567890
```

### 5. Install Dependencies

Run the following command to install the required Python packages:

```bash
pip install -r requirements.txt
```

### 6. Run the Application

Start the Flask application:

```bash
python app.pyw
```

The application will automatically create the default admin user on first run if it doesn't exist.

## Default Admin Credentials

- **Username**: `ganesh`
- **Password**: `ganesh123`

⚠️ **Important**: Change the admin password after first login in production!

## Troubleshooting

### Error: "SUPABASE_URL and SUPABASE_KEY must be set"
- Make sure you've created a `.env` file with the correct credentials
- Verify the credentials are correct in your Supabase dashboard

### Error: "relation does not exist"
- Make sure you've run the SQL migration script (`supabase_migration.sql`) in the Supabase SQL Editor
- Check that all three tables (`users`, `security_logs`, `network_stats`) exist in the Table Editor

### Connection Issues
- Verify your Supabase project is active (not paused)
- Check that your Project URL and API key are correct
- Ensure your network allows connections to Supabase

## Notes

- The Supabase free tier includes 500MB database storage and 2GB bandwidth, which should be sufficient for development
- For production, consider upgrading to a paid plan or implementing data retention policies
- All database operations now use Supabase instead of SQLite
- The local `firewall_system.db` file is no longer used

