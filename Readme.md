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
```

## DEVICES 🖥️

- **Air sensor**: measures air quality and sends $CO_2$ level each seconds.
- **Humidity / Temperature sensor**: measures humidity and temperature and sends a JSON with the information each 5-10 seconds.
- **Thermostat**: shows information about configured temperature for the house, allowing the user to modify it manually. It can also establish computed values based on the time of the day and the season.

To run an instance of a device use these commands:

```
cd .\devices
python air_sensor.py  # Air Sensor
python hum_temp.py    # Hum/Temp sensor
python thermostat.py  # Thermostat
```

## PLAFTORM 🌐

To view the platform application run this command. It has a web interface to manage the application:

```
cd .\platform
python app.py
```