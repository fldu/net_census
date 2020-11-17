import sqlalchemy
from sqlalchemy import MetaData, Table, Column, Integer, String
from dotenv import load_dotenv
from os.path import join, dirname
from os import getenv

dotenv_path = join(dirname(__file__), '/app/.env')
load_dotenv(dotenv_path)

db_name = getenv('MYSQL_DATABASE')
db_user = getenv('MYSQL_USER')
db_password = getenv('MYSQL_PASSWORD')

db_connector = sqlalchemy.create_engine(f"mysql+mysqlconnector://{db_user}:{db_password}@db/{db_name}")

#Tables scheme
meta_alive = MetaData()
alive = Table(
    "alive", meta_alive,
    Column("IP", String),
    Column("Timestamp", String)
)

meta_scan = MetaData()
scan = Table(
    "scan", meta_scan,
    Column("IP", String),
    Column("Port", String),
    Column("Timestamp", String)
)