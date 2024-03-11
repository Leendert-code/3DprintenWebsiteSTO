# /var/www/flask/app.wsgi
import sys
sys.path.insert(0, '/var/www/flask')

python_home = '/usr/bin/python'
sys.executable = python_home

from app import app as application  # Rename app to application for Gunicorn

# Debugging information
print("Python Executable:", sys.executable)
print("Python Path:", sys.path)