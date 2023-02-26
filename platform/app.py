from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import sys
import subprocess

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
with app.app_context():
    db = SQLAlchemy(app)

class Device(db.Model):
    __tablename__ = 'device' # nombre de la tabla en minúsculas
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    ubicacion = db.Column(db.String(200), nullable=False)
    tipo = db.Column(db.String(200), nullable=False)
    date_register = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return '<Device %r>' % self.nombre

@app.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)

if __name__ == "__main__":
    mqtt_client_process = subprocess.Popen([sys.executable, 'mqtt_client.py'])
    app.run(debug=False)
    mqtt_client_process.terminate()