from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from datetime import datetime
import sys
import subprocess

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
with app.app_context():
    db = SQLAlchemy(app)


class Device(db.Model):
    __tablename__ = 'device'  # nombre de la tabla en minúsculas
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


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200), nullable=False)
    aad = db.Column(db.String(200), nullable=True)
    time = db.Column(db.DateTime, default=datetime.now)
    device_id = db.Column(db.String(200), db.ForeignKey(
        'device.id'), nullable=False)
    device = db.relationship(
        'Device', backref=db.backref('messages', lazy=True))

    def __repr__(self):
        return '<Message %r>' % self.message

    def __init__(self, message, device, aad):
        self.message = message
        self.device = device
        self.aad = aad


@app.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)


@app.route('/remove/<string:device_id>', methods=['POST'])
def remove(device_id):
    device = Device.query.get(device_id)
    if device:
        db.session.delete(device)
        db.session.commit()
    return redirect('/')

@app.route('/device/<string:device_id>/messages', methods=['GET'])
def device(device_id):
    
    device = Device.query.get(device_id)
    messages = Message.query.filter_by(device_id=device_id).order_by(Message.time.desc()).limit(10).all()
    next_key_update = device.date_register + timedelta(minutes=5)

    # lógica para obtener la información del dispositivo correspondiente al ID
    return render_template('device_messages.html', device=device, messages=messages,next_key_update=next_key_update)

def recreate_db():
    with app.app_context():
        db.drop_all()
        db.create_all()


if __name__ == "__main__":
    recreate_db()
    mqtt_client_process = subprocess.Popen(
        [sys.executable, 'platform_mqtt.py'])
    app.run(debug=False)
    mqtt_client_process.terminate()
