# MarketCheck API Integration for PartsQuest
import requests
import json
import logging
from functools import lru_cache
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class MarketCheckAPI:
    """MarketCheck API service for dealership data"""
    
    BASE_URL = "https://api.marketcheck.com/v2"
    
    def __init__(self):
        self.api_key = "sgBUGqkzRrewBWfiG9IIiKRmxOhLnGD4Y"
        self.api_secret = "aJ9rOpb6JEeUAyXA"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PartsQuest/1.0 (https://partsquest.org)',
            'Authorization': f'Bearer {self.api_key}'
        })
    
    def get_dealerships_by_make(self, make: str, zip_code: str = None, radius: int = 50) -> List[Dict]:
        """Get dealerships for a specific vehicle make"""
        try:
            url = f"{self.BASE_URL}/dealerships/car"
            
            params = {
                'api_key': self.api_key,
                'make': make.lower(),
                'radius': radius
            }
            
            if zip_code:
                params['zip'] = zip_code
            
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            dealerships = []
            
            for dealer in data.get('dealers', []):
                dealership_info = {
                    'id': dealer.get('id'),
                    'name': dealer.get('dealer_name'),
                    'address': {
                        'street': dealer.get('address'),
                        'city': dealer.get('city'),
                        'state': dealer.get('state'),
                        'zip': dealer.get('zip'),
                        'country': dealer.get('country', 'US')
                    },
                    'contact': {
                        'phone': dealer.get('phone'),
                        'website': dealer.get('website')
                    },
                    'location': {
                        'latitude': dealer.get('latitude'),
                        'longitude': dealer.get('longitude'),
                        'distance': dealer.get('distance')
                    },
                    'make': make,
                    'type': 'dealership',
                    'source': 'marketcheck'
                }
                
                # Only include dealerships with phone numbers
                if dealership_info['contact']['phone']:
                    dealerships.append(dealership_info)
            
            logger.info(f"Retrieved {len(dealerships)} dealerships for {make}")
            return dealerships
            
        except Exception as e:
            logger.error(f"Error fetching dealerships for {make}: {e}")
            return []
    
    def get_dealerships_by_location(self, zip_code: str, radius: int = 25) -> List[Dict]:
        """Get all dealerships in a specific location"""
        try:
            url = f"{self.BASE_URL}/dealerships/car"
            
            params = {
                'api_key': self.api_key,
                'zip': zip_code,
                'radius': radius
            }
            
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            dealerships = []
            
            for dealer in data.get('dealers', []):
                dealership_info = {
                    'id': dealer.get('id'),
                    'name': dealer.get('dealer_name'),
                    'address': {
                        'street': dealer.get('address'),
                        'city': dealer.get('city'),
                        'state': dealer.get('state'),
                        'zip': dealer.get('zip'),
                        'country': dealer.get('country', 'US')
                    },
                    'contact': {
                        'phone': dealer.get('phone'),
                        'website': dealer.get('website')
                    },
                    'location': {
                        'latitude': dealer.get('latitude'),
                        'longitude': dealer.get('longitude'),
                        'distance': dealer.get('distance')
                    },
                    'makes': dealer.get('makes', []),
                    'type': 'dealership',
                    'source': 'marketcheck'
                }
                
                # Only include dealerships with phone numbers
                if dealership_info['contact']['phone']:
                    dealerships.append(dealership_info)
            
            logger.info(f"Retrieved {len(dealerships)} dealerships near {zip_code}")
            return dealerships
            
        except Exception as e:
            logger.error(f"Error fetching dealerships near {zip_code}: {e}")
            return []
    
    def decode_vin(self, vin: str) -> Dict:
        """Decode VIN using MarketCheck API"""
        try:
            url = f"{self.BASE_URL}/decode/car/{vin}/specs"
            
            params = {
                'api_key': self.api_key
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract vehicle specifications
            vehicle_specs = {
                'vin': vin,
                'year': data.get('year'),
                'make': data.get('make'),
                'model': data.get('model'),
                'trim': data.get('trim'),
                'body_type': data.get('body_type'),
                'engine': data.get('engine'),
                'transmission': data.get('transmission'),
                'drivetrain': data.get('drivetrain'),
                'fuel_type': data.get('fuel_type'),
                'source': 'marketcheck'
            }
            
            logger.info(f"Successfully decoded VIN: {vin}")
            return vehicle_specs
            
        except Exception as e:
            logger.error(f"Error decoding VIN {vin}: {e}")
            return {}

# Global instance
marketcheck_api = MarketCheckAPI()
