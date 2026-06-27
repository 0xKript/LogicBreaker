def calculate_total(items):
    # SAFE: pure local computation, no shared state, no request
    total = 0
    for item in items:
        if item.price >= 0:
            total += item.price
    return total
