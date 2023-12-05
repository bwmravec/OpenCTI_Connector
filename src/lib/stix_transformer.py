import logging
import re
from datetime import datetime
from urllib.parse import urlparse

from stix2 import Indicator, Bundle, Identity, Malware, Relationship, AttackPattern
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from stix_item import StixItemType, guess_type
from logger import init_logging

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
