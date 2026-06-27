# SAFE: yaml.safe_load never constructs arbitrary objects.
import yaml
def parse_config(raw):
    return yaml.safe_load(raw)
