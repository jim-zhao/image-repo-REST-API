from app_database import db, User, Files
import app_constants


from flask import Flask, request, make_response
from time import time
from functools import wraps
from hashlib import sha256
import jwt
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = app_constants.app_key
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{app_constants.database_uri}'
app.config['MAX_CONTENT_LENGTH'] = app_constants.max_upload_size
db.init_app(app) 


def hash_password(salt, password):
    """
    Hashes a password for storage in database. Variable salt for extra security
    """
    encoded_password = (salt + password).encode()
    hashed_password = sha256(encoded_password).hexdigest()
    return hashed_password   


def token_required(func):
    """
    Decorator for functions that require user authentication
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'x-access-token' not in request.headers:
            return make_response('No authentication token found', 401)
        
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        
        if not data['username'] or not data['expiry'] or not User.query.filter_by(username = data['username']).first():
            return make_response('Invalid token', 401)
        if data['expiry'] < time():
            return make_response('Expired token', 401)
        
        return func(data['username'], *args, **kwargs)
    return wrapper


# REST API is below
@app.route('/users', methods=['GET'])
def get_users():
    """
    Returns a JSON containing a list of all the users in the database
    """
    users = User.query.all()
    
    user_output = []    
    for user in users:
        user_output.append(user.username)        
    return make_response({'users' : user_output}, 200)


@app.route('/users', methods=['POST'])
def create_user():
    """
    Creates a username given a JSON in the format
    {
        "username" : INSERT USER STRING HERE,
        "password" : INSERT USER PASSWORD HERE
    }    
    """
    user_info = request.get_json()
    
    if not user_info or not user_info['username'] or not user_info['password']:
        return make_response('You must provide a valid username and password', 400)
    if User.query.filter_by(username = user_info['username']).first():
        return make_response('Current user already exists', 400)
    if len(user_info['username']) < app_constants.min_username_len: 
        return make_response('Username must be at least 3 characters', 400)
    
    hashed_password = hash_password(salt = user_info['username'][0:app_constants.min_username_len], password = user_info['password'])
    
    user_entry = User(username = user_info['username'], password = hashed_password)
    db.session.add(user_entry)
    db.session.commit()
    
    return make_response(f"User {user_info['username']} is created!", 200)


@app.route('/login', methods=['GET'])
def login():
    """
    Uses Basic Auth. Provide a username and password to recieve an access token to put in your HTTP header for authentication
    """
    credentials = request.authorization
    if not credentials or not credentials.username or not credentials.password:
        return make_response('You must provide a valid username and password', 401)
    
    user_info = User.query.filter_by(username = credentials.username).first()
    
    if not user_info or hash_password(user_info.username[0:app_constants.min_username_len], credentials.password) != user_info.password:
        return make_response('Invalid username/password combination', 401)
    
    token = jwt.encode({'username' : credentials.username, 
                        'expiry' : time() + app_constants.login_timeout_in_seconds}, 
                        app.config['SECRET_KEY'])
    return make_response({'x-access-token' : token.decode('UTF-8')}, 200)


@app.route('/images', methods=['POST'])
@token_required
def upload(current_user):
    """
    Uploads images to the server after performing a variety of checks.
    Private images are uploaded to the files folder under the user's name
    Public images are uploaded to the user's folder in the public folder
    """
    if 'public' in request.form:
        isPublic =  eval(request.form['public'])
    else:
        isPublic = False
        
    files = request.files
        
    error_log = []
    successful_uploads = 0
    upload_error = 200
    
    for file in files:
        # Security checks are in the block below
        # File size is checked by app.config['MAX_CONTENT_LENGTH'] to app_config.max_upload_size
        if len(file) > app_constants.max_filename_length:
            error_log.append(f'{file} was not uploaded as its name was too long')
            upload_error = 400
            continue
        if file.split(".")[-1].lower() not in app_constants.image_formats:
            error_log.append(f'{file} was not uploaded as it was not in one of the following formats {app_constants.image_formats}')
            upload_error = 415
            continue        
        if Files.query.filter_by(owner=current_user, file_name=file, public=isPublic).first():
            error_log.append(f'{file} was not uploaded as it already exists')
            upload_error = 409
            continue       
        
        try:
            if isPublic:
                directory = f'files\\{app_constants.public_folder_name}\\{current_user}'
            else:
                directory = f'files\\{app_constants.private_folder_name}\\{current_user}'
            if not os.path.exists(directory):
                os.makedirs(directory)
            files[file].save(f'{directory}\\{file}')
            
            new_file_entry = Files(owner=current_user, file_name=file, public=isPublic)
            db.session.add(new_file_entry)
            db.session.commit()
            successful_uploads += 1
        except:
            error_log.append(f'Cannot upload {file}')
            upload_error = 500
            
    
    if not error_log: # success
        return make_response({'successful uploads' : successful_uploads}, 200)
    elif successful_uploads == 0: # failure
        return make_response({'errors' : error_log}, upload_error)
    else: # partial success
        return make_response({'successful uploads' : successful_uploads,
                              'errors' : error_log}, 206)


@app.route('/images', methods=['GET'])
@token_required
def list(current_user):
    """
    Displays all the images that are accessable to the user. 
    This includes their own images as well as public images from another user 
    """
    current_user_files = Files.query.filter_by(owner=current_user)
    other_public_files = Files.query.filter(Files.owner!=current_user, Files.public==True)
    
    file_output = []    
    for current_user_file in current_user_files:
        file_output.append({'owner' : current_user_file.owner,
                            'file_name' : current_user_file.file_name,
                            'public' : current_user_file.public})
    
    for other_public_file in other_public_files:
        file_output.append({'owner' : other_public_file.owner,
                            'file_name' : other_public_file.file_name,
                            'public' : other_public_file.public})
        
    return make_response({'files' : file_output}, 200)
    

@app.route('/images', methods=['DELETE'])
@token_required
def delete(current_user):
    """
    Takes in a JSON that specifies the file(s) to delete. It is in the following format:
    {
        "files" = [1ST FILE TO DELETE, 2ND FILE TO DELETE, ...]
    }
    
    User can ONLY delete their files.
    """
    files_to_delete = request.get_json()
    successful_deletes = 0
    error_log = []
    delete_error = 200
    
    for file in files_to_delete['files']:
        fileEntry = Files.query.filter_by(owner=current_user, file_name=file).first()
        
        if fileEntry:
            if fileEntry.public:
                directory = f'files\\{app_constants.public_folder_name}\\{current_user}'
            else:
                directory = f'files\\{app_constants.private_folder_name}\\{current_user}'
            
            try:
                os.remove(f'{directory}\\{fileEntry.file_name}')
                db.session.delete(fileEntry)
                db.session.commit()
                successful_deletes += 1
            except:
                error_log.append(f'Cannot delete {file}')
                delete_error = 500
        else:
            error_log.append(f'Cannot delete {file}. Does not exist under your control')
            delete_error = 403
    
    if not error_log: # success
        return make_response({'successful deletes' : successful_deletes}, 200)
    elif successful_deletes == 0: # failure
        return make_response({'errors' : error_log}, delete_error)
    else: # partial success
        return make_response({'successful deletes' : successful_deletes,
                              'errors' : error_log}, 206)
        

if __name__ == '__main__':
    app.run(debug=True)