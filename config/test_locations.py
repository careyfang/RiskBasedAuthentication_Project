from geopy.distance import geodesic
import logging
logger = logging.getLogger(__name__)

# Common test locations with known coordinates
TEST_LOCATIONS = {
    # North America
    # United States
    'new_york': {
        'city': 'New York',
        'region': 'New York',
        'country': 'United States',
        'coords': (40.7128, -74.0060)
    },
    'los_angeles': {
        'city': 'Los Angeles',
        'region': 'California',
        'country': 'United States',
        'coords': (34.0522, -118.2437)
    },
    'san_francisco': {
        'city': 'San Francisco',
        'region': 'California',
        'country': 'United States',
        'coords': (37.7749, -122.4194)
    },
    'chicago': {
        'city': 'Chicago',
        'region': 'Illinois',
        'country': 'United States',
        'coords': (41.8781, -87.6298)
    },
    'houston': {
        'city': 'Houston',
        'region': 'Texas',
        'country': 'United States',
        'coords': (29.7604, -95.3698)
    },
    'seattle': {
        'city': 'Seattle',
        'region': 'Washington',
        'country': 'United States',
        'coords': (47.6062, -122.3321)
    },

    # Canada
    'toronto': {
        'city': 'Toronto',
        'region': 'Ontario',
        'country': 'Canada',
        'coords': (43.6532, -79.3832)
    },
    'vancouver': {
        'city': 'Vancouver',
        'region': 'British Columbia',
        'country': 'Canada',
        'coords': (49.2827, -123.1207)
    },
    'montreal': {
        'city': 'Montreal',
        'region': 'Quebec',
        'country': 'Canada',
        'coords': (45.5017, -73.5673)
    },

    # Europe
    # United Kingdom
    'london': {
        'city': 'London',
        'region': 'England',
        'country': 'United Kingdom',
        'coords': (51.5074, -0.1278)
    },
    'manchester': {
        'city': 'Manchester',
        'region': 'England',
        'country': 'United Kingdom',
        'coords': (53.4808, -2.2426)
    },
    'edinburgh': {
        'city': 'Edinburgh',
        'region': 'Scotland',
        'country': 'United Kingdom',
        'coords': (55.9533, -3.1883)
    },

    # France
    'paris': {
        'city': 'Paris',
        'region': 'Île-de-France',
        'country': 'France',
        'coords': (48.8566, 2.3522)
    },
    'lyon': {
        'city': 'Lyon',
        'region': 'Auvergne-Rhône-Alpes',
        'country': 'France',
        'coords': (45.7640, 4.8357)
    },
    'marseille': {
        'city': 'Marseille',
        'region': 'Provence-Alpes-Côte d\'Azur',
        'country': 'France',
        'coords': (43.2965, 5.3698)
    },

    # Germany
    'berlin': {
        'city': 'Berlin',
        'region': 'Berlin',
        'country': 'Germany',
        'coords': (52.5200, 13.4050)
    },
    'munich': {
        'city': 'Munich',
        'region': 'Bavaria',
        'country': 'Germany',
        'coords': (48.1351, 11.5820)
    },
    'hamburg': {
        'city': 'Hamburg',
        'region': 'Hamburg',
        'country': 'Germany',
        'coords': (53.5511, 9.9937)
    },

    # East Asia
    # Japan
    'tokyo': {
        'city': 'Tokyo',
        'region': 'Tokyo',
        'country': 'Japan',
        'coords': (35.6762, 139.6503)
    },
    'osaka': {
        'city': 'Osaka',
        'region': 'Osaka',
        'country': 'Japan',
        'coords': (34.6937, 135.5023)
    },
    'fukuoka': {
        'city': 'Fukuoka',
        'region': 'Fukuoka',
        'country': 'Japan',
        'coords': (33.5902, 130.4017)
    },
    'sapporo': {
        'city': 'Sapporo',
        'region': 'Hokkaido',
        'country': 'Japan',
        'coords': (43.0618, 141.3545)
    },

    # South Korea
    'seoul': {
        'city': 'Seoul',
        'region': 'Seoul',
        'country': 'South Korea',
        'coords': (37.5665, 126.9780)
    },
    'busan': {
        'city': 'Busan',
        'region': 'Busan',
        'country': 'South Korea',
        'coords': (35.1796, 129.0756)
    },
    'incheon': {
        'city': 'Incheon',
        'region': 'Incheon',
        'country': 'South Korea',
        'coords': (37.4563, 126.7052)
    },

    # Taiwan
    'taipei': {
        'city': 'Taipei',
        'region': 'Taipei',
        'country': 'Taiwan',
        'coords': (25.033, 121.565)
    },
    'new_taipei': {
        'city': 'New Taipei',
        'region': 'Taipei',
        'country': 'Taiwan',
        'coords': (25.012, 121.465)
    },
    'taichung': {
        'city': 'Taichung',
        'region': 'Taichung',
        'country': 'Taiwan',
        'coords': (24.1477, 120.6736)
    },
    'kaohsiung': {
        'city': 'Kaohsiung',
        'region': 'Kaohsiung',
        'country': 'Taiwan',
        'coords': (22.633, 120.266)
    },

    # Southeast Asia
    # Singapore
    'singapore': {
        'city': 'Singapore',
        'region': 'Singapore',
        'country': 'Singapore',
        'coords': (1.3521, 103.8198)
    },

    # Malaysia
    'kuala_lumpur': {
        'city': 'Kuala Lumpur',
        'region': 'Kuala Lumpur',
        'country': 'Malaysia',
        'coords': (3.1390, 101.6869)
    },
    'penang': {
        'city': 'George Town',
        'region': 'Penang',
        'country': 'Malaysia',
        'coords': (5.4141, 100.3288)
    },

    # Thailand
    'bangkok': {
        'city': 'Bangkok',
        'region': 'Bangkok',
        'country': 'Thailand',
        'coords': (13.7563, 100.5018)
    },
    'chiang_mai': {
        'city': 'Chiang Mai',
        'region': 'Chiang Mai',
        'country': 'Thailand',
        'coords': (18.7883, 98.9853)
    },

    # Oceania
    # Australia
    'sydney': {
        'city': 'Sydney',
        'region': 'New South Wales',
        'country': 'Australia',
        'coords': (-33.8688, 151.2093)
    },
    'melbourne': {
        'city': 'Melbourne',
        'region': 'Victoria',
        'country': 'Australia',
        'coords': (-37.8136, 144.9631)
    },
    'brisbane': {
        'city': 'Brisbane',
        'region': 'Queensland',
        'country': 'Australia',
        'coords': (-27.4698, 153.0251)
    },

    # New Zealand
    'auckland': {
        'city': 'Auckland',
        'region': 'Auckland',
        'country': 'New Zealand',
        'coords': (-36.8509, 174.7645)
    },
    'wellington': {
        'city': 'Wellington',
        'region': 'Wellington',
        'country': 'New Zealand',
        'coords': (-41.2866, 174.7756)
    },

    # Development/Testing
    'local': {
        'city': 'Local',
        'region': 'Local',
        'country': 'Local',
        'coords': (0, 0)
    }
}

# Cache of known location coordinates to reduce API calls
LOCATION_CACHE = {}

def get_cached_coords(city, region, country):
    """Get coordinates from cache or predefined test locations"""
    try:
        location_key = f"{city}, {region}, {country}"
        
        # Check cache first
        if location_key in LOCATION_CACHE:
            return LOCATION_CACHE[location_key]
        
        # Check test locations
        for loc in TEST_LOCATIONS.values():
            if (loc['city'].lower() == city.lower() and 
                loc['region'].lower() == region.lower() and 
                loc['country'].lower() == country.lower()):
                LOCATION_CACHE[location_key] = loc['coords']  # Cache the result
                return loc['coords']
        
        return None
        
    except Exception as e:
        logger.error(f"Error in get_cached_coords: {e}")
        return None

def get_test_location(location_key):
    """Get a test location by its key"""
    try:
        if location_key in TEST_LOCATIONS:
            return {
                'city': TEST_LOCATIONS[location_key]['city'],
                'region': TEST_LOCATIONS[location_key]['region'],
                'country': TEST_LOCATIONS[location_key]['country']
            }
        return None
    except Exception as e:
        logger.error(f"Error in get_test_location: {e}")
        return None

def calculate_distance(loc1, loc2):
    """Calculate distance between two locations"""
    try:
        coords1 = get_cached_coords(loc1['city'], loc1['region'], loc1['country'])
        coords2 = get_cached_coords(loc2['city'], loc2['region'], loc2['country'])
        
        if coords1 and coords2:
            return geodesic(coords1, coords2).miles
        return None
    except Exception as e:
        logger.error(f"Error calculating distance: {e}")
        return None 