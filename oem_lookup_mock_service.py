"""
Mock OEM Lookup Service for PartsQuest Backend

This provides a simple mock implementation of the OEM lookup functionality
to prevent import errors during deployment.
"""

class MockOEMLookupService:
    """Mock OEM lookup service that provides basic functionality without external dependencies"""
    
    def __init__(self):
        self.cache = {}
        print("✅ Mock OEM Lookup Service initialized")
    
    def lookup_oem_part(self, description, vehicle_data=None):
        """
        Mock OEM part lookup that returns a basic response
        
        Args:
            description (str): Part description to look up
            vehicle_data (dict): Vehicle information (optional)
            
        Returns:
            dict: Mock OEM lookup response
        """
        # Create a cache key
        cache_key = f"{description}_{vehicle_data}"
        
        # Check cache first
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Mock response
        mock_response = {
            'success': True,
            'description': description,
            'vehicle_data': vehicle_data,
            'oem_parts': [
                {
                    'part_number': f'OEM-{hash(description) % 10000}',
                    'description': description,
                    'manufacturer': 'Mock OEM',
                    'price': 99.99,
                    'availability': 'In Stock'
                }
            ],
            'source': 'mock_service',
            'timestamp': '2025-09-09T21:00:00Z'
        }
        
        # Cache the response
        self.cache[cache_key] = mock_response
        
        return mock_response
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            'cache_size': len(self.cache),
            'cached_lookups': list(self.cache.keys())
        }
    
    def clear_cache(self):
        """Clear the lookup cache"""
        self.cache.clear()
        return {'message': 'Cache cleared successfully'}

