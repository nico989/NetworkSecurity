from flask import Flask, render_template, request, flash, redirect, url_for
from flask_recaptcha import ReCaptcha

app = Flask(__name__)
recaptcha = ReCaptcha(app=app)

app.config.update(dict(
    SECRET_KEY = 'network-security-lab',
    RECAPTCHA_ENABLED = True,
    RECAPTCHA_SITE_KEY = "6LfLk28aAAAAAEG9BhD6qrglN9JZwUUpK2-VxG8c",
    RECAPTCHA_SECRET_KEY = "6LfLk28aAAAAAMfaxUBvjQ4kYXivovV3zY1BnwSX",
))

recaptcha = ReCaptcha()
recaptcha.init_app(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin' or not recaptcha.verify():
            flash('Invalid credentials or captcha failed. Please try again.')
        else:
            return redirect(url_for('success'))
    return render_template('login.html')

@app.route('/success')
def success():
    return render_template('success.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context=('cert_key/cert.pem', 'cert_key/key.pem'))
