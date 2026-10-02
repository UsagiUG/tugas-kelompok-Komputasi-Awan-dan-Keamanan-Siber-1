from datetime import datetime, timezone, timedelta
import random

def sensor_simulation(dummy_size_kb: int = 1) -> dict[str,float]:
  tz_wib = timezone(timedelta(hours=7))
  temperature = random.uniform(20.0, 40.0)
  air_humidity = random.uniform(40.0, 100.0)
  soil_moisture = random.uniform(0.0, 100.0)
  soil_ph = random.uniform(4.0, 7.0)

  return {
      'reading_timestamp': datetime.now(tz_wib).isoformat(),
      'temperature': temperature,
      'air_humidity': air_humidity,
      'soil_moisture': soil_moisture,
      'soil_ph': soil_ph,
      'dummy' : 'x' * 1024 * dummy_size_kb

      ## if prefer lower decimal count to save space
      # round('temperature': temperature, 3),
      # round('air_humidity': air_humidity, 3),
      # round('soil_moisture': soil_moisture, 3),
      # round('soil_ph': soil_ph, 3)
  }
