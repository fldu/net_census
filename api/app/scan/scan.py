import time
import pandas as pd
import logging
import subprocess
import re
import socket
import json
import ssl
import OpenSSL
import requests

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
        #Enrichment definition
        def enrichment(ip, port):
            dict_enrichment = {}
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%Z")
            dict_enrichment['IP'] = ip
            dict_enrichment['Port'] = port
            dict_enrichment['Timestamp'] = timestamp
            
            #Search for DNS record
            try:
                dict_enrichment['DNS'] = re.search(dn_nonsl, str(socket.gethostbyaddr(ip))).group(0)
            except:
                dict_enrichment['DNS'] = "null"
            
            #Search if there is a webservice and if it has SSL
            hostname = ""
            dict_ssl = {}

            if dict_enrichment['DNS'] != 'null':
                hostname = dict_enrichment['DNS']
            else:
                hostname = dict_enrichment['IP']

            try:
                try:
                    r = requests.get(f"http://{hostname}:{self.port}", timeout=5, allow_redirects=False, verify=False)
                    dict_enrichment['HTTP service'] = 'Yes'
                    dict_enrichment['HTTP status code'] = str(r.status_code)

                except requests.exceptions.ConnectionError:
                    r = requests.get(f"https://{hostname}:{self.port}", timeout=5, allow_redirects=False, verify=False)
                    dict_enrichment['HTTP service'] = 'Yes'
                    dict_enrichment['HTTP status code'] = str(r.status_code)

                except requests.exceptions.Timeout:
                    dict_enrichment['HTTP service'] = 'Timeout'
                    dict_enrichment['HTTP status code'] = 'null'

                except Exception as e:
                    dict_enrichment['HTTP service'] = 'No'
                    dict_enrichment['HTTP status code'] = 'null'

                try:
                    sock = socket.create_connection((hostname, port), timeout=5)

                    try:
                        data = json.dumps(ssl.create_default_context().wrap_socket(sock, server_hostname=hostname).getpeercert())
                        cert = ssl.get_server_certificate((hostname, port))
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                        cert_notafter = x509.get_notAfter().decode("utf-8")
                        cert_notafter = time.strptime(cert_notafter, '%Y%m%d%H%M%SZ')
                        cert_notafter = time.strftime("%Y-%m-%d %H:%M:%S", cert_notafter)
                        dict_ssl['data'] = data 
                        dict_ssl['expiration'] = cert_notafter
                        dict_ssl['error'] = None

                    except ssl.SSLCertVerificationError as sslvererr:
                        cert = ssl.get_server_certificate((hostname, port))
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                        cert_notafter = x509.get_notAfter().decode("utf-8")
                        cert_notafter = time.strptime(cert_notafter, '%Y%m%d%H%M%SZ')
                        cert_notafter = time.strftime("%Y-%m-%d %H:%M:%S", cert_notafter)
                        error = sslvererr.verify_message
                        dict_ssl['data'] = str(sslvererr) 
                        dict_ssl['expiration'] = cert_notafter
                        dict_ssl['error'] = error

                    except ssl.SSLError as sslerr:
                        error = sslerr.reason
                        dict_ssl['data'] = str(sslerr) 
                        dict_ssl['expiration'] = None
                        dict_ssl['error'] = error

                    except ssl.SSLEOFError as sslerr:
                        dict_ssl['data'] = str(sslerr) 
                        dict_ssl['expiration'] = None
                        dict_ssl['error'] = None

                    except socket.timeout:
                        dict_ssl['data'] = 'Timeout' 
                        dict_ssl['expiration'] = None
                        dict_ssl['error'] = None
                        
                    except socket.gaierror:
                        dict_ssl['data'] = 'Host not available' 
                        dict_ssl['expiration'] = None
                        dict_ssl['error'] = None

                    except:
                        dict_ssl['data'] = 'SSL check failure' 
                        dict_ssl['expiration'] = None
                        dict_ssl['error'] = None

                except socket.timeout:
                    dict_ssl['data'] = 'Timeout' 
                    dict_ssl['expiration'] = None
                    dict_ssl['error'] = None

                except ConnectionRefusedError:
                    dict_ssl['data'] = 'Connection refused' 
                    dict_ssl['expiration'] = None
                    dict_ssl['error'] = None

                except Exception as e:
                    dict_ssl['data'] = 'Uncaught exception' 
                    dict_ssl['expiration'] = None
                    dict_ssl['error'] = str(e)
            
                if dict_ssl['data']:
                    if dict_ssl['data'].startswith('{'):
                        dict_enrichment["SSL present?"] = 'Yes'
                        dict_enrichment["SSL expiration date"] = dict_ssl['expiration']
                        dict_enrichment["SSL valid?"] = 'Yes'

                    elif dict_ssl['data'].startswith('UNSUPPORTED'):
                        dict_enrichment["SSL present?"] = 'Legacy Protocol'
                        dict_enrichment["SSL expiration date"] = dict_ssl['expiration']
                        dict_enrichment["SSL valid?"] = 'No - Unsupported protocol'

                    elif dict_ssl['data'].startswith('[SSL: CERTIFICATE_VERIFY_FAILED]'):
                        dict_enrichment["SSL present?"] = 'Yes'
                        dict_enrichment["SSL expiration date"] = dict_ssl['expiration']
                        dict_enrichment["SSL valid?"] = f'No - {dict_ssl["error"]}'

                    elif dict_ssl['data'].startswith('[SSL: WRONG_VERSION_NUMBER]'):
                        dict_enrichment["SSL present?"] = 'No'
                        dict_enrichment["SSL expiration date"] = 'null'
                        dict_enrichment["SSL valid?"] = 'null'

                    elif dict_ssl['data'].startswith('EOF'):
                        dict_enrichment["SSL present?"] = 'No'
                        dict_enrichment["SSL expiration date"] = 'null'
                        dict_enrichment["SSL valid?"] = 'null'

                    elif dict_ssl['data'].startswith('Timeout'):
                        dict_enrichment["SSL present?"] = 'Handshake timed out'
                        dict_enrichment["SSL expiration date"] = 'Handshake timed out'
                        dict_enrichment["SSL valid?"] = 'Handshake timed out'

                    else:
                        dict_enrichment["SSL present?"] = 'Yes'
                        dict_enrichment["SSL expiration date"] = 'Uncaught exception'
                        dict_enrichment["SSL valid?"] = f'No - {dict_ssl["error"]}'
                else:
                    dict_enrichment["SSL present?"] = "Failure"
                    dict_enrichment["SSL expiration date"] = "Failure"
                    dict_enrichment["SSL valid?"] = "Failure"
            except Exception as e:
                dict_enrichment['HTTP service'] = f"No"
                dict_enrichment['HTTP status code'] = 'null'
                dict_enrichment["SSL present?"] = "No"
                dict_enrichment["SSL expiration date"] = "null"
                dict_enrichment["SSL valid?"] = "null"
            #More enrichment here
            return dict_enrichment

        try:
            logging.info(f"scan:scan: {self.ip_range} on port {self.port} with rate {self.rate} is beginning")
            output = subprocess.check_output(["/app/scan/scan.sh", f"{self.ip_range}", f"{self.rate}", f"{self.port}"]).decode("utf-8").split("\n")
            output_sql = pd.DataFrame(columns=[
                "IP", 
                "Port", 
                "Timestamp",
                "DNS",
                "HTTP service",
                "HTTP status code",
                "SSL present?",
                "SSL expiration date",
                "SSL valid?",
                ])
            for ip in output:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%Z")
                    output_sql = output_sql.append(enrichment(ip, self.port), ignore_index = True)
            try:
                df_from_sql = pd.read_sql(f"SELECT * FROM scan", con=db_connector)
            except:
                df_from_sql = pd.DataFrame(columns=[
                    "IP", 
                    "Port", 
                    "Timestamp",
                    "DNS",
                    "HTTP service",
                    "HTTP status code",
                    "SSL present?",
                    "SSL expiration date",
                    "SSL valid?",
                ])
            try:
                new_df_to_sql = pd.concat([output_sql, df_from_sql], ignore_index = True)
                new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates(subset=['IP', 'Port'], keep="last")
                new_df_to_sql.to_sql(con=db_connector, name="scan", if_exists = "replace", index=False)
                #Here, we update alive table
                new_df_to_sql = new_df_to_sql[["IP", "Timestamp"]]
                try:
                    df_from_sql = pd.read_sql(f"SELECT * FROM alive", con=db_connector)
                except:
                    df_from_sql = pd.DataFrame(columns=["IP", "Timestamp"])
                try:
                    new_df_to_sql = new_df_to_sql.sort_values("Timestamp").drop_duplicates("IP", keep="last")
                    new_df_to_sql.to_sql(con=db_connector, name="alive", if_exists = "replace", index=False)
                    logging.info(f"scan: {self.ip_range} finished")
                    return True
                except Exception as e:
                    logging.error(f"scan {self.ip_range} stopped with error: {e}")
                    return False
            except Exception as e:
                logging.error(f"scan {self.ip_range} stopped with error: {e}")
                return False
        except Exception as e:
            logging.error(f"scan {self.ip_range} stopped with error: {e}")
            return False

    def retrieve(self):
        if (self.ip is not None) and (self.port is None):
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

        elif (self.ip is None) and (self.port is not None):
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

        elif (self.ip is not None) and (self.port is not None):
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
