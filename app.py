from flask import Flask, render_template, request
from cryptography.fernet import Fernet
import sqlite3
import os
import random
import string
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

KEY = Fernet.generate_key()
fernet = Fernet(KEY)

conn = sqlite3.connect('database.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE,
    type TEXT,
    data BLOB
)
''')

conn.commit()

def generate_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encode', methods=['GET', 'POST'])
def encode():

    if request.method == 'POST':

        content_type = request.form.get('type')
        code = generate_code()

        if content_type == 'text':

            text = request.form.get('text')

            encrypted = fernet.encrypt(text.encode())

            cursor.execute(
                'INSERT INTO secrets (code, type, data) VALUES (?, ?, ?)',
                (code, 'text', encrypted)
            )

            conn.commit()

            return render_template('result.html', code=code)

        elif content_type == 'image':

            image = request.files['image']

            if image:

                filename = secure_filename(image.filename)

                filepath = os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    filename
                )

                image.save(filepath)

                with open(filepath, 'rb') as f:
                    image_data = f.read()

                encrypted = fernet.encrypt(image_data)

                cursor.execute(
                    'INSERT INTO secrets (code, type, data) VALUES (?, ?, ?)',
                    (code, 'image', encrypted)
                )

                conn.commit()

                return render_template('result.html', code=code)

    return render_template('encode.html')

@app.route('/decode', methods=['GET', 'POST'])
def decode():

    if request.method == 'POST':

        code = request.form.get('code')

        cursor.execute(
            'SELECT type, data FROM secrets WHERE code=?',
            (code,)
        )

        result = cursor.fetchone()

        if result:

            content_type, encrypted_data = result

            decrypted = fernet.decrypt(encrypted_data)

            if content_type == 'text':

                decoded_text = decrypted.decode()

                return render_template(
                    'decode.html',
                    text=decoded_text,
                    found=True
                )

            elif content_type == 'image':

                output_path = os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    f'{code}.png'
                )

                with open(output_path, 'wb') as f:
                    f.write(decrypted)

                image_path = f'uploads/{code}.png'

                return render_template(
                    'decode.html',
                    image=image_path,
                    found=True
                )

        else:

            return render_template(
                'decode.html',
                found=False
            )

    return render_template('decode.html')

if __name__ == '__main__':
    app.run(debug=True)