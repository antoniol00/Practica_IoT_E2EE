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
    id = db.Column(db.String(200), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(200), nullable=False)
    encryption_mode = db.Column(db.String(4), nullable=False)
    encryption_algorithm = db.Column(db.String(10), nullable=False)
    hash_algorithm = db.Column(db.String(10), nullable=False)
    dh_algorithm = db.Column(db.String(10), nullable=False)
    date_register = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return '<Device %r>' % self.nombre

    def __init__(self, id, name, location, type, encryption_mode, encryption_algorithm, hash_algorithm, dh_algorithm):
        self.id = id
        self.name = name
        self.location = location
        self.type = type
        self.encryption_mode = encryption_mode
        self.encryption_algorithm = encryption_algorithm
        self.hash_algorithm = hash_algorithm
        self.dh_algorithm = dh_algorithm

@app.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)

if __name__ == "__main__":
    mqtt_client_process = subprocess.Popen([sys.executable, 'platform_mqtt.py'])
    app.run(debug=False)
    mqtt_client_process.terminate()