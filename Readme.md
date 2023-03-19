## INSTALLATION ⚙️

In Windows:
```
python -m venv env
.\env\Scripts\activate.bat      #Command prompt
.\env\Scripts\Activate.ps1      #Powershell
pip install -r requirements.txt
```

In Linux:
```
python -m venv env
source env/Scripts/activate
pip install -r requirements.txt
```

Then, you must create a `.env` file in the root directory containing this information:

```
MQTT_BROKER=###     # URL for broker connection
MQTT_PORT=#####     # Port used
BROKER_USER=###     # User identification
BROKER_PASS=###     # Password
RENEWAL_TIME=###    # Key renewal time (in seconds)
```

## DEVICES 🖥️

- **Air sensor**: measures air quality and sends $CO_2$ level each seconds.
- **Humidity / Temperature sensor**: measures humidity and temperature and sends a JSON with the information each 5-10 seconds.

To run an instance of a device use this commands (you can specify --verbose to show all messages):

```
cd .\devices
python build_sensor.py
```

## PLATFORM 🌐

To view the platform application run this command. It has a web interface to manage the application (the database linked to the application will be created automatically and recreated each time the application is run):

```
cd .\platform
python app.py
```
