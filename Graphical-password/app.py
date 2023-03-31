import random
import sqlite3
import bcrypt
import logging

from flask import Flask, render_template, request, session, redirect, url_for, flash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'

N = 3
logging.basicConfig(filename='app.log', level=logging.DEBUG)


def get_password_images():
    images = random.sample(range(1, 10), N * N)
    logging.debug(f"Selected Images: {images}")
    p_images = []
    for i in range(0, N * N, N):
        p_images.append(images[i:i + N])
    logging.debug(f"Password Images: {p_images}")
    return p_images


@app.route('/')
def welcome():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('identifier.sqlite') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            session['username'] = username
            return redirect(url_for('welcome'))
        else:
            p_images = get_password_images()
            return render_template('login.html', error='Invalid username or password', p_images=p_images)
    else:
        p_images = get_password_images()
        return render_template('login.html', p_images=p_images)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('identifier.sqlite') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                p_images = get_password_images()
                return render_template('signup.html', error='Username already taken', p_images=p_images)
            else:
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                session['username'] = username
        return redirect(url_for('welcome'))
    else:
        p_images = get_password_images()
        return render_template('signup.html', p_images=p_images)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()


