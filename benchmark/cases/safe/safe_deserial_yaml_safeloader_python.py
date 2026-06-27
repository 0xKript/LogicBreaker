# SAFE: yaml.load with an explicit SafeLoader cannot construct arbitrary objects.
# Trap: it deserialises untrusted request data (where the default loader or
# unsafe_load would be RCE), but SafeLoader restricts it to plain scalars/maps.
import yaml
from flask import request
def load_config():
    raw = request.data
    return str(yaml.load(raw, Loader=yaml.SafeLoader))
