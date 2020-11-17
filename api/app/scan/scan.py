import time
import pandas as pd
import logging
import subprocess
import re

from sqlalchemy.sql import text, select
from db.database import db_connector, scan

class Scan:
    def __init__(
        self,
        ip_range = None,
        ip = None,
        rate = None
    ):
        self.ip_range = ip_range
        self.ip = ip
        self.rate = rate

    def scan(self):
        try:
            logging.info(f"scan:scan: {self.ip_range} with rate {self.rate} is beginning")
            output = subprocess.check_output(["/app/scan/scan.sh", f"{self.ip_range}", f"{self.rate}"]).decode("utf-8").split("\n")
            output_sql = pd.DataFrame(columns=["IP", "Port", "Timestamp"])
            for ip_port in output:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}", ip_port):
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%Z")
                    ip_port_split = ip_port.split(':')
                    output_sql = output_sql.append({"IP": ip_port_split[0], "Port": ip_port_split[1], "Timestamp": timestamp}, ignore_index = True)
            try:
                df_from_sql = pd.read_sql(f"SELECT * FROM scan", con=db_connector)
            except:
                df_from_sql = pd.DataFrame(columns=["IP", "Port", "Timestamp"])
            new_df_to_sql = pd.concat([output_sql, df_from_sql], ignore_index = True)
            new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates(subset=['IP', 'Port'], keep="last")
            new_df_to_sql.to_sql(con=db_connector, name="scan", if_exists = "replace", index=False)
            logging.info(f"scan: {self.ip_range} finished")
            return True
        except Exception as e:
            logging.error(f"scan {self.ip_range} stopped with error: {e}")
            return False

    def retrieve(self):
        try:
            logging.info(f"scan:retrieve info for {self.ip}")
            data_from_sql = db_connector.execute(select([scan]).where(alive.columns.IP == self.ip)).fetchall()
            returned_ports = []
            for data in data_from_sql:
                returned_ports.append(data[1])
            returned_data = {self.ip: returned_ports}
            return returned_data
        except Exception as e:
            logging.error(f"alive:retrieve {self.ip} stopped with error: {e}")
            return False