import psycopg2
from config import DB_HOST, DB_NAME, DB_USER, DB_PASSWORD

def obtener_conexion():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
