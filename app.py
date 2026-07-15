from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from data_pb2 import AccountPersonalShowInfo
    from google.protobuf.descriptor import FieldDescriptor
    import uid_generator_pb2
    import GetWishListItems_pb2
except ImportError as e:
    print(f"Import error: {e}")
    class Dummy:
        pass
    AccountPersonalShowInfo = Dummy
    FieldDescriptor = Dummy
    uid_generator_pb2 = Dummy
    GetWishListItems_pb2 = Dummy

app = Flask(__name__)

# Cache for faster responses
jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()
cache = {}
cache_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)

# JWT API endpoint
JWT_API_URL = "https://bishal-jwt-api.vercel.app/token"

# Region-specific credentials
REGION_CREDENTIALS = {
    "IND": {
        "uid": "4519188408",
        "password": "1A6ECD9C7C977CF900EC0E22288040EEBA07C082AB80CC7DE96051E6CD0BBF68"
    },
    "BD": {
        "uid": "4732876335",
        "password": "6B83A422316D71BE2F30F56C8C70521B375C243B600FD92E0B35077E180931D7"
    }
}

# Pre-fetch tokens on startup
def pre_fetch_tokens():
    for region in REGION_CREDENTIALS:
        try:
            ensure_jwt_token_sync(region)
        except:
            pass

def proto_to_dict(message):
    result = {}
    try:
        for field in getattr(message.DESCRIPTOR, 'fields', []):
            value = getattr(message, field.name)
            val_type = type(value).__name__
            
            if 'MapContainer' in val_type:
                map_result = {}
                for k, v in value.items():
                    if hasattr(v, 'DESCRIPTOR'):
                        map_result[k] = proto_to_dict(v)
                    elif isinstance(v, bytes):
                        map_result[k] = binascii.hexlify(v).decode('utf-8')
                    else:
                        map_result[k] = v
                result[field.name] = map_result
                
            elif 'Repeated' in val_type:
                list_result = []
                for item in value:
                    if hasattr(item, 'DESCRIPTOR'):
                        list_result.append(proto_to_dict(item))
                    elif isinstance(item, bytes):
                        list_result.append(binascii.hexlify(item).decode('utf-8'))
                    else:
                        list_result.append(item)
                result[field.name] = list_result
                
            elif hasattr(value, 'DESCRIPTOR'):
                result[field.name] = proto_to_dict(value)
                
            elif getattr(field, 'type', None) == 14:
                try:
                    result[field.name] = field.enum_type.values_by_number[value].name
                except:
                    result[field.name] = value
                    
            elif isinstance(value, bytes):
                result[field.name] = binascii.hexlify(value).decode('utf-8') if value else ""
                
            else:
                result[field.name] = value
    except Exception as e:
        print(f"Proto to dict error: {e}")
    return result

def ensure_jwt_token_sync(region):
    global jwt_tokens, jwt_expiry
    current_time = time.time()

    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
        return jwt_tokens[region]

    with jwt_lock:
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
            return jwt_tokens[region]

        credentials = REGION_CREDENTIALS.get(region)
        if not credentials:
            return None

        try:
            response = requests.get(
                JWT_API_URL,
                params={
                    "uid": credentials["uid"],
                    "password": credentials["password"]
                },
                timeout=5
            )
            response.raise_for_status()

            data = response.json()
            token = data.get("token") or data.get("jwt_token")

            if token:
                jwt_tokens[region] = token
                jwt_expiry[region] = current_time + 300
                return token

        except Exception as e:
            print(f"[JWT] Request error for {region}: {e}")

    return jwt_tokens.get(region)

def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, region):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        data = bytes.fromhex(idd)
        response = requests.post(endpoint, headers=headers, data=data, timeout=5)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"[API] Request to {endpoint} failed: {e}")
        raise

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "endpoints": {
            "/info": "GET - Get player info (uid, region parameters)",
            "/wishlist": "GET - Get wishlist items (uid, region parameters)"
        },
        "example": "/info?uid=1234567890&region=IND"
    })

@app.route('/info', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Check cache first
        cache_key = f"{uid}_{region}"
        with cache_lock:
            if cache_key in cache:
                cached_data, cache_time = cache[cache_key]
                if time.time() - cache_time < 60:  # Cache for 60 seconds
                    return jsonify(cached_data)
        
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        encrypted_hex = encrypt_aes(hex_data, default_key, default_iv)
        
        api_response = apis(encrypted_hex, region)
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        result = proto_to_dict(message)
        
        basic_info = result.get('basic_info', {})
        
        filtered_response = {
            "uid": basic_info.get('account_id'),
            "name": basic_info.get('nickname'),
            "level": basic_info.get('level'),
            "liked": basic_info.get('liked'),
            "server": region
        }
        
        # Store in cache
        with cache_lock:
            cache[cache_key] = (filtered_response, time.time())
        
        return jsonify(filtered_response)
    
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, default_key, default_iv)
        
        base_endpoint = get_api_endpoint(region)
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")
        
        token = ensure_jwt_token_sync(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(wishlist_url, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=5)
        response.raise_for_status()
        resp_hex = response.content.hex()
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(resp_hex))
        
        result = proto_to_dict(res)
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

# Pre-fetch tokens on startup
threading.Thread(target=pre_fetch_tokens, daemon=True).start()

# For Vercel
def handler(request, *args, **kwargs):
    return app(request, *args, **kwargs)

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 1080))
    app.run(host="0.0.0.0", port=port, threaded=True)