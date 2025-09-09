# NHTSA vPIC Vehicle API Integration
import requests
import json
from functools import lru_cache
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class NHTSAVehicleAPI:
    """NHTSA vPIC Vehicle API service for PartsQuest"""
    
    BASE_URL = "https://vpic.nhtsa.dot.gov/api/vehicles"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PartsQuest/1.0 (https://partsquest.org)'
        })
    
    @lru_cache(maxsize=128)
    def get_makes(self, year=None):
        """Get all vehicle makes, optionally filtered by year"""
        try:
            if year:
                url = f"{self.BASE_URL}/GetMakesForVehicleType/car?format=json&year={year}"
            else:
                url = f"{self.BASE_URL}/GetAllMakes?format=json"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            makes = []
            
            for item in data.get('Results', []):
                make_name = item.get('Make_Name') or item.get('MakeName')
                make_id = item.get('Make_ID') or item.get('MakeId')
                
                if make_name and make_id:
                    makes.append({
                        'id': make_id,
                        'name': make_name
                    })
            
            # Sort by name
            makes.sort(key=lambda x: x['name'])
            
            logger.info(f"Retrieved {len(makes)} vehicle makes")
            return makes
            
        except Exception as e:
            logger.error(f"Error fetching vehicle makes: {e}")
            return []
    
    @lru_cache(maxsize=256)
    def get_models(self, make_id, year=None):
        """Get models for a specific make and year"""
        try:
            if year:
                url = f"{self.BASE_URL}/GetModelsForMakeIdYear/makeId/{make_id}/year/{year}?format=json"
            else:
                url = f"{self.BASE_URL}/GetModelsForMakeId/{make_id}?format=json"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            models = []
            
            for item in data.get('Results', []):
                model_name = item.get('Model_Name')
                model_id = item.get('Model_ID')
                
                if model_name and model_id:
                    models.append({
                        'id': model_id,
                        'name': model_name
                    })
            
            # Sort by name and remove duplicates
            unique_models = {}
            for model in models:
                unique_models[model['name']] = model
            
            models = list(unique_models.values())
            models.sort(key=lambda x: x['name'])
            
            logger.info(f"Retrieved {len(models)} models for make_id {make_id}")
            return models
            
        except Exception as e:
            logger.error(f"Error fetching models for make {make_id}: {e}")
            return []
    
    def get_years(self):
        """Get available vehicle years"""
        current_year = datetime.now().year
        years = list(range(1981, current_year + 2))  # 1981 to next year
        return [{'id': year, 'name': str(year)} for year in reversed(years)]
    
    def decode_vin(self, vin):
        """Decode VIN to get vehicle specifications"""
        try:
            url = f"{self.BASE_URL}/DecodeVin/{vin}?format=json"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            results = data.get('Results', [])
            
            # Extract key vehicle information
            vehicle_info = {}
            
            for item in results:
                variable = item.get('Variable')
                value = item.get('Value')
                
                if variable and value and value != 'Not Applicable':
                    if variable == 'Make':
                        vehicle_info['make'] = value
                    elif variable == 'Model':
                        vehicle_info['model'] = value
                    elif variable == 'Model Year':
                        vehicle_info['year'] = value
                    elif variable == 'Vehicle Type':
                        vehicle_info['type'] = value
                    elif variable == 'Body Class':
                        vehicle_info['body_class'] = value
                    elif variable == 'Engine Number of Cylinders':
                        vehicle_info['cylinders'] = value
                    elif variable == 'Displacement (L)':
                        vehicle_info['displacement'] = value
            
            logger.info(f"Successfully decoded VIN: {vin}")
            return vehicle_info
            
        except Exception as e:
            logger.error(f"Error decoding VIN {vin}: {e}")
            return {}

# Global instance
nhtsa_api = NHTSAVehicleAPI()
