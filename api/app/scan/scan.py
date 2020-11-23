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
        rate = None,
        port = None
    ):
        self.ip_range = ip_range
        self.ip = ip
        self.rate = rate
        self.port = port

    def scan(self):
        try:
            logging.info(f"scan:scan: {self.ip_range} on port {self.port} with rate {self.rate} is beginning")
            output = subprocess.check_output(["/app/scan/scan.sh", f"{self.ip_range}", f"{self.rate}", f"{self.port}"]).decode("utf-8").split("\n")
            output_sql = pd.DataFrame(columns=["IP", "Port", "Timestamp"])
            for ip_port in output:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}", ip_port):
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%Z")
                    ip_port_split = ip_port.split(':')
                    output_sql = output_sql.append({"IP": ip_port_split[0], "Port": self.port, "Timestamp": timestamp}, ignore_index = True)
            try:
                df_from_sql = pd.read_sql(f"SELECT * FROM scan", con=db_connector)
            except:
                df_from_sql = pd.DataFrame(columns=["IP", "Port", "Timestamp"])
            new_df_to_sql = pd.concat([output_sql, df_from_sql], ignore_index = True)
            new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates(subset=['IP', 'Port'], keep="last")
            new_df_to_sql.to_sql(con=db_connector, name="scan", if_exists = "replace", index=False)
            #Here, we update alive table
            new_df_to_sql = new_df_to_sql[["IP", "Timestamp"]]
            try:
                df_from_sql = pd.read_sql(f"SELECT * FROM alive", con=db_connector)
            except:
                df_from_sql = pd.DataFrame(columns=["IP", "Timestamp"])
            new_df_to_sql = pd.concat([output_sql, df_from_sql], ignore_index = True)
            new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates("IP", keep="last")
            new_df_to_sql.to_sql(con=db_connector, name="scan", if_exists = "replace", index=False)
            logging.info(f"scan: {self.ip_range} finished")
            return True
        except Exception as e:
            logging.error(f"scan {self.ip_range} stopped with error: {e}")
            return False

    def retrieve(self):
        if self.ip is not None and self.port is None:
            try:
                logging.info(f"scan:retrieve info for {self.ip}")
                data_from_sql = db_connector.execute(select([scan]).where(scan.columns.IP == self.ip)).fetchall()
                returned_ports = []
                for data in data_from_sql:
                    returned_ports.append(data[1])
                return {self.ip: returned_ports}
            except Exception as e:
                logging.error(f"alive:retrieve ip {self.ip} stopped with error: {e}")
                return {self.ip: 'error'}

        elif self.ip is None and self.port is not None:
            try:
                logging.info(f"scan:retrieve info for {self.ip}")
                data_from_sql = db_connector.execute(select([scan]).where(scan.columns.Port == self.port)).fetchall()
                returned_ips = []
                for data in data_from_sql:
                    returned_ips.append(data[1])
                return {self.port: returned_ips}
            except Exception as e:
                logging.error(f"alive:retrieve port {self.port} stopped with error: {e}")
                return {self.port: 'error'}

        elif self.ip is not None and self.port is not None:
            try:
                logging.info(f"scan:retrieve info for {self.ip} and {self.port}")
                data_from_sql = db_connector.execute(select([scan]).where(scan.columns.IP == self.ip).where(scan.columns.Port == self.port)).fetchall()
                if len(data_from_sql) > 0:
                    return{self.ip: self.port, 'open': 'yes'}
                else:
                    return{self.ip: self.port, 'open': 'no'}
            except Exception as e:
                logging.error(f"alive:retrieve info for {self.ip} port {self.port} stopped with error: {e}")
                return {self.ip: self.port, 'open': 'error'}

        else:
            return False
