"""Hidden: hardcoded DB credentials in connection string."""
DB_URL = "postgresql://admin:s3cr3tP@ss@db.example.com:5432/prod"
REDIS_URL = "redis://:p4ssw0rd123@cache.internal:6379/0"

def get_db():
    import sqlalchemy
    return sqlalchemy.create_engine(DB_URL)
