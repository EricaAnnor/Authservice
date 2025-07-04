from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os

load_dotenv()



db_pool = pool.SimpleConnectionPool(
    minconn=0,
    maxconn=10,
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT"),
    cursor_factory=RealDictCursor

)

def get_connection():
    pool = db_pool.getconn()
    return pool

def return_connection(pool):
    db_pool.putconn(pool)
