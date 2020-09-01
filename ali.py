import json
import logging
import smtplib
import ssl
import subprocess
import sys
import datetime
import yaml
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
from aliyunsdkcore.client import AcsClient

logging.basicConfig(filename='ddns.log',
                    level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S')

config = None


def read_yaml(filename):
    r"""
    Read specified yaml file into an object.
    :param filename: relative file name, e.g. "conf/config.yaml"
    :return: yaml data
    """
    try:
        yaml_file = open(filename, "rb")
        yaml_data = yaml.safe_load(yaml_file)
        yaml_file.close()
        logging.info('Successfully loaded yaml configuration.')
        return yaml_data
    except Exception as e:
        logging.error("Unable to read configuration file.")
        logging.error(e)
        sys.exit(-1)


def get_aliyun_access_client(_id, secret, region):
    r"""
    Create an authenticated client for API calls to Aliyun.
    :param _id: access key id
    :param secret: secret of the access key
    :param region: e.g. "cn-hangzhou", "cn-shenzhen"
    :return: access client object
    """
    try:
        client = AcsClient(_id, secret, region)
        logging.info('Successfully obtained access client instance.')
        return client
    except Exception as e:
        logging.error("Aliyun access key authentication failed.")
        logging.error(e)
        sys.exit(-1)


def get_dns_record_id(client, domain, host, ip_address):
    r"""
    Get DNS RecordId from Aliyun
    :param client: client object
    :param domain: domain name, e.g. "dongs.xyz"
    :param host: host, e.g. "www"
    :param ip_address: new Ip address, e.g. "127.0.0.1"
    :return: record id
    """
    try:
        request = DescribeDomainRecordsRequest()
        request.set_accept_format('json')
        request.set_DomainName(domain)
        request.set_PageSize(100)
        response = client.do_action_with_exception(request)
        json_data = json.loads(str(response, encoding='utf-8'))

        for RecordId in json_data['DomainRecords']['Record']:
            if host == RecordId['RR']:
                logging.info("Found a matched RecordId: {_record_id}.".format(
                    _record_id=RecordId["RecordId"]
                ))
                if ip_address == RecordId['Value']:
                    return None
                else:
                    return RecordId['RecordId']

    except Exception as e:
        logging.error("Unable to get RecordId.")
        logging.error(e)
        sys.exit(-1)


def update_domain_record(client, host, domain, _type, ip_address, record_id):
    r"""
    Update domain information
    :param client: client object
    :param host: e.g. 'www'
    :param domain: e.g. 'dongs.xyz'
    :param _type: e.g. 'A', 'CNAME'
    :param ip_address: e.g. '127.0.0.1'
    :param record_id: record id from Aliyun
    """
    try:
        request = UpdateDomainRecordRequest()
        request.set_accept_format('json')
        request.set_Value(ip_address)
        request.set_Type(_type)
        request.set_RR(host)
        request.set_RecordId(record_id)
        response = client.do_action_with_exception(request)
        logging.info("Successfully updated domain record: {_host}.{_domain} ({__type} record) to {_ip_address}.".format(
            _host=host,
            _domain=domain,
            __type=_type,
            _ip_address=ip_address
        ))
        logging.debug(response)
    except Exception as e:
        logging.error("Failed to update domain record: {_host}.{_domain} ({__type} record) to {_ip_address}.".format(
            _host=host,
            _domain=domain,
            __type=_type,
            _ip_address=ip_address
        ))
        logging.error(e)


def get_local_ip_cache():
    r"""
    Get IP address local cache
    :return: string literal of IP address or None if no cache found
    """
    try:
        ip_cache_file = open(".ipaddress", 'r')
        ip_cache = ip_cache_file.read()
        ip_cache_file.close()
        logging.info(
            "Successfully loaded IP cache: {ip_cache}.".format(ip_cache=ip_cache))
        return ip_cache
    except Exception as e:
        logging.error("Unable to load IP cache, does it exist?")
        logging.error(e)
        return None


def write_local_ip_cache(ip_address):
    try:
        ip_cache_file = open(".ipaddress", 'w')
        ip_cache_file.write(ip_address)
        ip_cache_file.close()
        logging.info("Successfully wrote IP cache: {ip_address}.".format(
            ip_address=ip_address))
    except Exception as e:
        logging.error("Unable to write IP local cache.")
        logging.error(e)


def main():
    t_start = datetime.datetime.now()
    logging.info(
        "--- Task started at {time}".format(time=t_start.strftime("%Y-%m-%d %H:%M:%S %f")))
    # Configuration section
    global config
    config = read_yaml('config.yaml')
    access_key = config['User']['AccessKey']
    secret = config['User']['Secret']
    region = config['User']['Region']
    domain = config['Domain']['Name']
    host = config['Domain']['Host']
    _type = config['Domain']['Type']

    ip_address = subprocess.check_output(
        ["curl", "-s", "whatismyip.akamai.com"]).decode("utf-8")
    ip_cache = get_local_ip_cache()
    if ip_cache == ip_address:
        logging.info("IP address up to date, same as the cached content: {ip_address}.".format(
            ip_address=ip_address))
        logging.info("Skip updating remote DNS.")
    else:
        write_local_ip_cache(ip_address)
        client = get_aliyun_access_client(access_key, secret, region)
        record_id = get_dns_record_id(client, domain, host, ip_address)
        if record_id is None:
            logging.info("No DNS record to update, skip and exit")
        else:
            update_domain_record(client, host, domain,
                                 _type, ip_address, record_id)

    t_end = datetime.datetime.now()
    logging.info(
        "--- Task ended at: {time}".format(time=t_end.strftime("%Y-%m-%d %H:%M:%S %f")))
    return 0


if __name__ == "__main__":
    main()
