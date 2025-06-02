import time, hmac, base64, hashlib, struct
from datetime import datetime
 
def dynamic_truncate(raw_bytes, length):
    """Per https://tools.ietf.org/html/rfc4226#section-5.3"""
    offset = raw_bytes[19] & 0x0f
    decimal_value = ((raw_bytes[offset] & 0x7f) << 24 |
                     (raw_bytes[offset+1] << 16) |
                     (raw_bytes[offset+2] << 8) |
                     (raw_bytes[offset+3]))
    return str(decimal_value)[-length:] 

def pack_time(counter):
    """Converts integer time into bytes"""
    return struct.pack(">Q", int(counter))
 
 
secret32='WPHR3VQGVNGRICXN'
secret_bytes = base64.b32decode(secret32.upper())

epoch = int(time.time())
counter = epoch // 30
print('Python datetime:', datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S'))
print('Python epoch:', epoch)
print('Python counter:', counter)
packed_counter = pack_time(counter)
print('Packed counter:', packed_counter)

raw_hmac = hmac.new(secret_bytes, packed_counter, hashlib.sha1).digest()
print('HMAC:', raw_hmac)
print('TOTP:', dynamic_truncate(raw_hmac, 6))
 
# ## Verify, if you have oathtool installed
# import os
# os.system("oathtool --totp -b '%s'" % secret32)
