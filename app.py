from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time

from data_pb2 import AccountPersonalShowInfo
from google.protobuf.descriptor import FieldDescriptor
import uid_generator_pb2
import GetWishListItems_pb2 

app = Flask(__name__)

jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()

# Cache for faster responses
response_cache = {}
cache_lock = threading.Lock()
CACHE_TTL = 30

# Region credentials
REGION_CREDENTIALS = {
    "BD": {
        "uid": "4712672050",
        "password": "MEHEDI_X_AURAKA6FLOFQ5"
    },
    "IND": {
        "uid": "4519188408",
        "password": "1A6ECD9C7C977CF900EC0E22288040EEBA07C082AB80CC7DE96051E6CD0BBF68"
    }
}

JWT_ENDPOINTS = {
    "BD": "https://bishal-jwt-api.vercel.app/token?uid={uid}&password={password}",
    "IND": "https://bishal-jwt-api.vercel.app/token?uid={uid}&password={password}",
    "BR": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4345418798&password=JOBAYAR_GK6VJ",
    "US": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
    "SAC": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349229968&password=GARENA_KI_MKC_50WO1_BY_KALLU_CODEX_22WFM",
    "ID": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349239376&password=GARENA_KI_MKC_2RTZ5_BY_KALLU_CODEX_GTYZX",
    "PK": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349240944&password=GARENA_KI_MKC_1VK2D_BY_KALLU_CODEX_53S3N",
    "VN": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349242942&password=GARENA_KI_MKC_B9L28_BY_KALLU_CODEX_HQ3T8",
    "ME": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349244853&password=GARENA_KI_MKC_MFD4N_BY_KALLU_CODEX_2Y9F4",
    "TH": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349247913&password=GARENA_KI_MKC_2123L_BY_KALLU_CODEX_SCKTB",
    "default": "https://jwt-system-ff.vercel.app/guest_to_jwt?uid=4349249859&password=GARENA_KI_MKC_VO3QR_BY_KALLU_CODEX_RTAWR"
}

API_ENDPOINTS = {
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

default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def proto_to_dict(message):
    result = {}
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
    return result

def get_jwt_url(region):
    if region in REGION_CREDENTIALS:
        creds = REGION_CREDENTIALS[region]
        return JWT_ENDPOINTS.get(region, JWT_ENDPOINTS["default"]).format(
            uid=creds["uid"],
            password=creds["password"]
        )
    return JWT_ENDPOINTS.get(region, JWT_ENDPOINTS["default"])

def ensure_jwt_token_sync(region):
    global jwt_tokens, jwt_expiry
    current_time = time.time()

    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
        return jwt_tokens[region]

    with jwt_lock:
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
            return jwt_tokens[region]

        url = get_jwt_url(region)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            token = data.get("jwt_token") or data.get("token")
            if token:
                jwt_tokens[region] = token
                jwt_expiry[region] = current_time + 300
                return token
        except Exception as e:
            print(f"[JWT Error] {region}: {e}")
    return jwt_tokens.get(region)

def get_api_endpoint(region):
    return API_ENDPOINTS.get(region, API_ENDPOINTS["default"])

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
        raise Exception(f"Failed to get JWT token for {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    response = requests.post(endpoint, headers=headers, data=bytes.fromhex(idd), timeout=10)
    response.raise_for_status()
    return response.content.hex()

def get_cached_response(cache_key):
    with cache_lock:
        if cache_key in response_cache:
            data, timestamp = response_cache[cache_key]
            if time.time() - timestamp < CACHE_TTL:
                return data
            del response_cache[cache_key]
    return None

def set_cached_response(cache_key, data):
    with cache_lock:
        response_cache[cache_key] = (data, time.time())

@app.route('/info', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter required"}), 400
        
        cache_key = f"info_{uid}_{region}"
        cached = get_cached_response(cache_key)
        if cached:
            return jsonify(cached)
        
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = apis(encrypted_hex, region)
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        result = proto_to_dict(message)
        set_cached_response(cache_key, result)
        return jsonify(result)
    
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter required"}), 400
        
        cache_key = f"wishlist_{uid}_{region}"
        cached = get_cached_response(cache_key)
        if cached:
            return jsonify(cached)

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        base_endpoint = get_api_endpoint(region)
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")
        
        token = ensure_jwt_token_sync(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(wishlist_url, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=10)
        response.raise_for_status()
        resp_hex = response.content.hex()
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(resp_hex))
        result = proto_to_dict(res)
        set_cached_response(cache_key, result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, threaded=True)