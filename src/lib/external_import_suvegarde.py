import os
import sys
import time
from datetime import datetime
import requests  #to use APIs GET
#from stix2 import *
from pycti import OpenCTIConnectorHelper
import logging
import re
from datetime import datetime
from urllib.parse import urlparse

from stix2 import Indicator, Bundle, Identity, Malware, Relationship, AttackPattern, Bundle
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
import re
import socket
import validators
from fqdn import FQDN
from enum import Enum
from urllib.parse import urlparse
import logging
import multiprocessing.util


class PluginFormatter(logging.Formatter):
    """Custom logger to colorize messages."""

    COLOR_RED = 31
    COLOR_GREEN = 32
    COLOR_YELLOW = 33
    COLOR_BLUE = 34
    COLOR_PURPLE = 35

    LOG_COLORS = {
        logging.DEBUG: COLOR_BLUE,
        logging.INFO: COLOR_GREEN,
        logging.WARNING: COLOR_YELLOW,
        logging.ERROR: COLOR_RED,
        logging.CRITICAL: COLOR_PURPLE,
    }

    def __init__(self, fmt=None, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)

    def __colorize(self, s, color=COLOR_RED):
        """Colorize a characters string."""
        retval = chr(0x1B) + "[0;%dm" % color + str(s) + chr(0x1B) + "[0m"
        return retval

    def format(self, record):
        """A custom format handler to colorize log level names."""
        colorno = PluginFormatter.LOG_COLORS.get(record.levelno, None)
        if colorno is not None:
            record.levelname = self.__colorize(record.levelname, colorno)
        msg = super(PluginFormatter, self).format(record)
        return msg

def customize_logger(logger, fmt=multiprocessing.util.DEFAULT_LOGGING_FORMAT):
    assert len(logger.handlers) == 1
    handler = logging.StreamHandler()
    formatter = PluginFormatter(fmt)
    handler.setFormatter(formatter)
    logger.handlers[0] = handler

def get_logging():
    return logging

def init_logging(loglevel = logging.INFO):
    """Initialize the logging subsystem, at the specified level."""
    # Set the proper verbosity level
    if  isinstance(loglevel, int):
        numeric_loglevel = loglevel
    else:
        numeric_loglevel = getattr(logging, loglevel.upper(), None)
    logging.basicConfig(level=numeric_loglevel)

    # Install our own logging handler
    log_format = "[%(asctime)s] %(levelname)s : %(message)s"
    customize_logger(logging.root, fmt=log_format)


class StixItemType(Enum):
    UNKNOWN         =   0,
    IPADDR          =   1,
    DOMAIN          =   2,
    URL             =   3,
    SHA256          =   4,
    MD5             =   5,
    SHA1            =   6,


def guess_type(value):
        if not value or len(value) == 0:
            return StixItemType.UNKNOWN, "unknown"

        if re.match("^[a-f0-9]{64}$", value, flags=re.IGNORECASE):
            return StixItemType.SHA256, "SHA256"

        if re.match("^[a-f0-9]{40}$", value, flags=re.IGNORECASE):
            return StixItemType.SHA1, "SHA1"

        if re.match("^[a-f0-9]{32}$", value, flags=re.IGNORECASE):
            return StixItemType.MD5, "MD5"

        try:
            socket.inet_aton(value)
            return StixItemType.IPADDR, "IPv4"
        except socket.error:
            pass

        if len(value) <= 255:
            fqdn = FQDN(value)
            if fqdn.is_valid:
                return StixItemType.DOMAIN, "domain"

        if validators.url(value):
            return StixItemType.URL, "URL"

        return StixItemType.UNKNOWN, "unknown"



def ioc_to_title_and_pattern(ioc_value):
    ioc_type = guess_type(ioc_value)[0]

    if ioc_type == StixItemType.SHA256:
        return f"Malicious SHA256 - {ioc_value}", f"[file:hashes.'SHA-256' = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.SHA1:
        return f"Malicious SHA1 - {ioc_value}", f"[file:hashes.'SHA-1' = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.MD5:
        return f"Malicious MD5 - {ioc_value}", f"[file:hashes.MD5 = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.IPADDR:
        return f"Malicious IP - {ioc_value}", f"[ipv4-addr:value = '{ioc_value}']"
    elif ioc_type == StixItemType.DOMAIN:
        return f"Malicious domain - {ioc_value}", f"[domain-name:value = '{ioc_value.lower()}']"
    elif ioc_type == StixItemType.URL:
        pattern = f"[url:value = '{ioc_value}']"
        if '\\' in pattern:
            pattern = pattern.replace('\\', '\\\\')
        return f"Malicious URL - {ioc_value}", pattern
    else:
        raise Exception(f"Unknown IOC type for value '{ioc_value}'")


def ids_to_mitre_attack_patterns(ids):
    aps = []
    for mid in ids.split(","):
        if not re.match(r"T\d{4}(\.\d{3})?$", mid):
            logging.warning(f"Skipping invalid MITRE technique ID: {mid}")
            continue
        if mid.startswith('T0'):
            url = f"https://collaborate.mitre.org/attackics/index.php/Technique/{mid}"
        else:
            url = f"https://attack.mitre.org/techniques/{mid}/"
        attack_pattern = AttackPattern(name=mid, external_references=[{"url": url, "source_name": "mitre-attack", "external_id": mid}])
        aps.append(attack_pattern)
    return aps

def create_stix_bundle(threat_name, description, iocs, author, source=None, url=None, mitre=None, tlp=None):
    init_logging()

    identity = Identity(name=author)
    objects = [identity]
    malware = Malware(name=threat_name, is_family=False, description=description)

    if url:
        if source:
            source_name = source
        else:
            source_name = urlparse(url).netloc
        malware_with_ref = malware.new_version(external_references=[{"source_name": source_name, "url": url}])
        objects.append(malware_with_ref)
    else:
        objects.append(malware)

    tlp_mark = None
    if tlp:
        supported_tlps = {
            'clear': TLP_WHITE,
            'white': TLP_WHITE,
            'green': TLP_GREEN,
            'amber': TLP_AMBER,
            'red': TLP_RED,
        }
        tlp_str = tlp.lower()
        if tlp_str.startswith('tlp:'):
            tlp_str = tlp_str[4:]
        if tlp_str not in supported_tlps:
            logging.critical(f'"{tlp}" TLP code is not supported. Terminating script.')
            return None
        tlp_mark = supported_tlps[tlp_str]

        objects.append(tlp_mark)

    aps = []
    if mitre:
        aps = ids_to_mitre_attack_patterns(mitre)
        objects.extend(aps)
    for ioc in iocs:
        try:
            title, pattern = ioc_to_title_and_pattern(ioc)
        except Exception as e:
            logging.error(f"Skipping indicator: {e}")
            continue
        description = " ".join(title.split()[:2]) + f" involved with {threat_name}"
        indicator = Indicator(labels="malicious-activity", pattern_type='stix', pattern=pattern,
                              valid_from=datetime.now(), description=description, name=title,
                              created_by_ref=identity, object_marking_refs=tlp_mark)
        relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=malware.id)
        objects.append(indicator)
        objects.append(relationship)
        for ap in aps:
            relationship = Relationship(relationship_type='indicates', source_ref=indicator.id, target_ref=ap.id)
            objects.append(relationship)

    return Bundle(objects=objects)


class ExternalImportConnector:
    """Specific external-import connectorS

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        # Specific connector attributes for external import connectors
        try:
            self.interval = os.environ.get("CONNECTOR_RUN_EVERY", None).lower()
            self.helper.log_info(
                f"Verifying integrity of the CONNECTOR_RUN_EVERY value: '{self.interval}'"
            )
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as _:
            msg = f"Error ({_}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            self.helper.log_error(msg)
            raise ValueError(msg)

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if update_existing_data.lower() in ["true", "false"]:
            self.update_existing_data = update_existing_data.lower()
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"


    ############# COLLECTING DATA    ################################
    def _collect_intelligence(self) -> list:
        time_now = datetime.now()
        current_time = time_now.strftime("%H:%M")

        print("The current date and time is :", current_time)
        url = 'http://api.blocklist.de/getlast.php?time='+current_time
        response = requests.get(url)
        if response.status_code == 200:
            data = response.text.splitlines()
            message = (
                f"{self.helper.connect_name} connector successfully retrieved data and converting it to STIX2 Format "
                + str(time_now)
            )
            self.helper.log_info(message)
            ##Calling the stix transformer
            data_to_bundle = create_stix_bundle("IPV4","IP adress", data, "api.blocklist")

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
            self.helper.log_info(message)


    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD return always the interval in seconds. If the connector is execting that the parameter is received as hoursUncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        if unit == "d":
            # In days:
            return int(value) * 60 * 60 * 24
        elif unit == "h":
            # In hours:
            return int(value) * 60 * 60
        elif unit == "m":
            # In minutes:
            return int(value) * 60
        elif unit == "s":
            # In seconds:
            return int(value)

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    ############################### HERE I NEED TO DO THE DATA COLLECTION  ######################################################################

                    try:
                        # Performing the collection of intelligence
                        bundle_objects = self._collect_intelligence()
                        bundle = Bundle(
                            objects=bundle_objects, allow_custom=True
                        ).serialize()

                        self.helper.log_info(
                            f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                        )
                        self.helper.send_stix2_bundle(
                            bundle,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))

                    ###############################################################################################################################################

                    # Store the current timestamp as a last run
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.log_info(message)

                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = timestamp
                    else:
                        current_state = {"last_run": timestamp}
                    self.helper.set_state(current_state)

                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self._get_interval() / 60 / 60, 2))
                        + " hours"
                    )
                else:
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60, 2))
                        + " hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)