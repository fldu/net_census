import time
import pandas as pd
import logging
import subprocess
import re

from sqlalchemy.sql import text, select
from db.database import db_connector, alive

class Alive():
    def __init__(
        self,
        ip_range = None,
        ip = None
    ):
        self.ip_range = ip_range
        self.ip = ip

    def ping(self):
        try:
            logging.info(f"alive:ping: {self.ip_range} is beginning")
            output = subprocess.check_output(["/app/alive/ping.sh", f"{self.ip_range}"]).decode("utf-8").split("\n")
            output_sql = pd.DataFrame(columns=["IP", "Timestamp"])
            for ip in output:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%Z")
                    output_sql = output_sql.append({"IP": ip, "Timestamp": timestamp}, ignore_index = True)
            try:
                df_from_sql = pd.read_sql(f"SELECT * FROM alive", con=db_connector)
            except:
                df_from_sql = pd.DataFrame(columns=["IP", "Timestamp"])
            new_df_to_sql = pd.concat([output_sql, df_from_sql], ignore_index = True)
            new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates("IP", keep="last")
            new_df_to_sql.to_sql(con=db_connector, name="alive", if_exists = "replace", index=False)
            logging.info(f"ping: {self.ip_range} finished")
            return True
        except Exception as e:
            logging.error(f"ping: {self.ip_range} stopped with error: {e}")
            return False

    def retrieve_ip(self):
        try:
            logging.info(f"alive:retrieve info for {self.ip}")
            data_from_sql = db_connector.execute(select([alive]).where(alive.columns.IP == self.ip)).fetchall()
            timestamp = data_from_sql[0][1]
            return timestamp
        except Exception as e:
            logging.error(f"alive:retrieve {self.ip} stopped with error: {e}")
            return False

