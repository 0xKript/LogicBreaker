# SAFE: internal helper, no request handling, id is an internal arg
def find_in_cache(cache, item_id):
    return cache.get(item_id)

def load_config(file_id):
    configs = {1: "a.conf", 2: "b.conf"}
    return configs.get(file_id)
