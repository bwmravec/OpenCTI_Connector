# coding: utf-8

import os
import sys
import yaml
import time
import requests

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Indicator,Bundle

class blacklistIPConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        #Extra config
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        print(self.update_existing_data)
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
        )
        self.blacklistIP_interval = get_config_variable(
            "BLACKLISTIP_INTERVAL", ["blacklistIP", "interval"], config, True
        )
        self.blacklistIP_url = get_config_variable(
            "BLACKLISTIP_URL", ["blacklistIP", "url"], config, False
        )

    def get_interval(self) -> int:
        return int(self.blacklistIP_interval) * 60 * 60 * 24
    
    def _collect_intelligence(self,URL_GIVEN) -> list:
        time_now = datetime.now()
        current_time = time_now.strftime("%H:%M")

        self.helper.log_info("The current date and time is :", current_time)
        self.helper.log_info("The type of current time variable is :", type(current_time))
        self.helper.log_info("The type of current URL is :", type(URL_GIVEN))
        #url = 'http://api.blocklist.de/getlast.php?time='+current_time
        url = URL_GIVEN+current_time
        self.helper.log_info("The final URL is :", url)
        response = requests.get(url)
        self.helper.log_info(response.status_code)
        #self.helper.log_info(response.text)
        #self.helper.log_info(response.content)
        if response.status_code == 200:
            #data = response.text.splitlines()
            message = (
                f"{self.helper.connect_name} connector successfully retrieved data and converting it to STIX2 Format "
                + str(time_now)
            )
            #self.helper.log_info(message)
            ##Calling the stix transformer
            data_to_bundle = self.create_stix_objects(response.text)
            print("HELOOOOOOOOOOOOOOOOO THESE ARE THE DATA TRANSFORMED TO STIX :"+data_to_bundle)
            message = (
                f"{self.helper.connect_name} Formated to STIX2 bundle "
                + str(time_now)
            )
            self.helper.log_info(message)
            return data_to_bundle
        else:
            message = (
                f"{self.helper.connect_name} Failed to retrieve data on "
                + str(time_now)
            )
            self.helper.log_warning(message)

    def create_stix_objects(self, data):
        stix_objects = []
        for line in data.splitlines():
            #timestamp = int(time.time())
            time_now = datetime.now()
            current_time = datetime.now().isoformat(timespec='seconds')
            # Assuming each line contains an IP address and other data
            ip = line.split(',')[0]  # Adjust this based on the actual data format
            indicator = Indicator(
                pattern="[ipv4-addr:value = '{}']".format(ip),
                pattern_type="stix",
                valid_from=time_now  # Adjust the timestamp as needed
            )
            stix_objects.append(indicator)

        return Bundle(objects=stix_objects).serialize()

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run) > ((int(self.blacklistIP_interval) - 1) * 60 * 60 * 24)
            ):
                self.helper.log_info("Connector will run!")

                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "blacklistIP run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                # Retrieve blacklistIP stix file
                if (
                    self.blacklistIP_url is not None
                    and len(self.blacklistIP_url) > 0
                ):
                    blacklist_data = self._collect_intelligence(self.blacklistIP_url)
                    #self.helper.log_debug(blacklist_data)
                    self.send_bundle(work_id, blacklist_data)

                # Store the current timestamp as a last run
                message = "Connector successfully run, storing last_run as " + str(
                    timestamp
                )
                self.helper.log_info(message)
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def send_bundle(self, work_id: str, serialized_bundle) -> None:
        try:
            self.helper.send_stix2_bundle(
                bundle=serialized_bundle,
                entities_types=self.helper.connect_scope,
                #update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def run(self) -> None:
        self.helper.log_info("Fetching BlacklistIP framework...")

        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

if __name__ == "__main__":
    try:
        connector = blacklistIPConnector()
        connector.run()
    except Exception as e:
        print(e)
        #time.sleep(10)
        exit(0)