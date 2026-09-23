#!/usr/bin/env bash
set -euo pipefail

# A new Render SQLite preview database has no tables, so migrate before the
# web server starts. Set RUN_MIGRATIONS=0 only for a pre-migrated database.
if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
  echo "Running migrations..."
  python manage.py migrate --noinput
fi

# Start the application
exec gunicorn --bind "0.0.0.0:${PORT}" sist_project.wsgi:application
