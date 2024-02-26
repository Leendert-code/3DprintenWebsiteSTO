# /var/www/flask/app.wsgi
import sys
sys.path.insert(0, '/var/www/flask')

python_home = '/usr/bin/python'
sys.executable = python_home
# app.wsgi

from app import app as application

# Debugging information
print("Python Executable:", sys.executable)
print("Python Path:", sys.path)
