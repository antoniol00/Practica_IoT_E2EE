## INSTALLATION ⚙️

In Windows:
```
.\env\Scripts\activate.bat
pip install -r requirements.txt
```

In Linux:
```
source env/Scripts/activate
pip install -r requirements.txt
```

## DEVICES 🖥️

- **Air sensor**: measures air quality and sends $CO_2$ level each seconds.
- **Humidity / Temperature sensor**: measures humidity and temperature and sends a JSON with the information each 5-10 seconds.
- **Thermostat**: shows information about configured temperature for the house, allowing the user to modify it manually. It can also establish computed values based on the time of the day and the season.

To run an instance of a device use these commands:

```
python .\devices\air_sensor.py  # Air Sensor
python .\devices\hum_temp.py    # Hum/Temp sensor
python .\devices\thermostat.py  # Thermostat
```

## PLAFTORM 🌐

To view the platform application run this command. It has a web interface to manage the application:

```
flask --app .\platform\app.py run
```