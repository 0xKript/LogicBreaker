# VULN: yaml.unsafe_load deserializes arbitrary Python objects (CWE-502).
import yaml
def parse_config(raw):
    return yaml.unsafe_load(raw)
