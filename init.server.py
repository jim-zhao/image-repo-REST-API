import rest_api
import os

# Set up
with rest_api.app.app_context():
    rest_api.db.create_all()
    
os.mkdir("files")
os.mkdir("files\\private")
os.mkdir("files\\public")