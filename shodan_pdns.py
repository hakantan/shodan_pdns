import pandas as pd
import requests
import json
import time
from pathlib import Path
import datetime
import yaml
import sys
from os import chdir
import logging

# enter auth
with open('apikeys.yaml', 'r') as api_keys:
    load_keys = yaml.safe_load(api_keys)
    SHODAN_KEY = load_keys['apikeys']['shodan']['key']

# setting up shodan
# for now, I'm only interested in SSL-information, so I'll use the host method
# for more: https://developer.shodan.io/api

SHODAN_URL = "https://api.shodan.io"
HOST_SEARCH = '/shodan/host/search'

# this ssl-cert was being used by APT32
# check this link for more information: https://web.br.de/interaktiv/ocean-lotus/en/
SEARCH_QUERY = 'ssl:196113228a9c7dc615a43c4431dc2bb327c43b2c'

# results will be stored in this folder later on
SEARCH_RESULTS = '/results'
SEARCH_LOGS = '/logs'

# Preparing the file for saving, we need a timestamp
TIME_NOW = datetime.datetime.today().strftime('%Y-%m-%d')


def shodan_search(query):
    params = {'key': SHODAN_KEY,
              'query': query}

    resp = requests.get(SHODAN_URL + HOST_SEARCH, params=params)

    # 200: Request was OK!
    if resp.status_code == 200:
        results = []
        json_response = resp.json()

        # Shodan stores its results in a dict with the key 'matches'
        # But if the list stored in that dict has a length of 0
        # the request was successful, but there were no results.
        if len(json_response['matches']) == 0:
            logger.debug('Request went through, no results.')
            return None

        else:
            logger.debug('Request went through.')
            for match in json_response['matches']:
                results.append(match)
            return results

    # if there is something wrong with the request, give back the error
    else:
        logger.error(
            f'There was a problem with the request: The error code is: {resp.status_code}')
        return None


def process_results(search_results):
    processed_results = []

    # Shodan API returns a lot of information.
    # We just need some pieces of that.
    for result in search_results:

        dict = {}
        dict['hash'] = result['hash']
        dict['hostnames'] = result['hostnames']
        dict['ip_str'] = result['ip_str']
        dict['asn'] = result['asn']
        dict['isp'] = result['isp']
        dict['domains'] = result['domains']
        dict['timestamp'] = result['timestamp']
        dict['ssl_fingerprint'] = result['ssl']['cert']['fingerprint']['sha1']
        dict['ssl_serial'] = result['ssl']['cert']['serial']
        processed_results.append(dict)

    return processed_results


def compare_dataframes(new_dataframe, old_dataframe):
    # creating a variable to use at the end of the function
    final_df = None

    # Cycling through the new results. We'll start with the first item
    # and check the complete dataframe, one by one. Then we'll repeat.
    # Two loops are needed.
    for index_one, row_one in new_dataframe.iterrows():
        logger.debug(
            'Starting first loop, with IP address "{}".'.format(row_one['ip_str']))

        # Since we haven't found anything yet, this variable equals False
        found = False

        for index_two, row_two in old_dataframe.iterrows():

            # For now, we're only interested in changes in IP.
            # In the future, we might look at changes in ISP and/or ASN
            if row_one['ip_str'] in row_two['ip_str']:

                # since we have found a match, we had this result already. We're breaking out of the loop and moving on.
                found = True
                logger.debug(
                    f'Variable found is {found}, breaking out of loop.')
                break

            # Since we're looping through a complete list, many of the results won't match.
            # Say 123.123.123.13 is part of the DataFrame, but in the fourth row,
            # you'll go through the loop three times without finding a match.
            else:
                pass

        # If we've gone through all the items and still haven't found anything, then we got a new item.
        # We'll populate the empty dataframe with the results.
        if not found:
            logger.debug(f'Populating the "final_df" with new findings.')
            final_df = query_df.append(new_dataframe.iloc[index_one])

    # check if final_df is still None. If not, there are some results to work with.
    if final_df is not None:
        return final_df

    else:
        logger.info('Final df was not created.')
        return None


def create_folder(query, result, logger):

    # the queries have a colon, that's not a workable solution for storing them on disk
    # so we're going to replace them with an underscore when creating the folder
    # the exist_ok-option checks if the file exists and doesn't raise an error if it does.
    query_path = query.replace(':', '_')
    Path(query_path).mkdir(exist_ok=True)

    result_path = query_path + result
    Path(result_path).mkdir(exist_ok=True)

    logging_path = query_path + logger
    Path(logging_path).mkdir(exist_ok=True)

    return query_path, result_path


def change_folder(start_here, switch_to):
    #logger.debug('Switching directories. Right now in:', Path.cwd())
    chdir(start_here)
    #logger.debug('Switching directories. Right now in:', Path.cwd())
    chdir(switch_to)
    #logger.debug('Switching directories. Right now in:', Path.cwd())


def create_empty_dataframe():
    empty_dataframe = pd.DataFrame(columns=['hash', 'hostnames', 'ip_str', 'asn', 'isp', 'domains', 'timestamp',
                                            'ssl_fingerprint', 'ssl_serial'])
    logger.debug('An empty dataframe was created.')
    return empty_dataframe


def start_logging():
    # setting up logger
    logs = logging.getLogger(__name__)
    # Log levels at
    # https://docs.python.org/3/library/logging.html#levels
    logs.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s %(funcName)s %(message)s')

    file_handler = logging.FileHandler(
        f'.{SEARCH_LOGS}/script_{TIME_NOW}.log')
    file_handler.setFormatter(formatter)
    logs.addHandler(file_handler)
    return logs


if __name__ == '__main__':

    # create folders to save files in
    start_folder = Path.cwd()
    working_folders = create_folder(SEARCH_QUERY, SEARCH_RESULTS, SEARCH_LOGS)
    main_folder = working_folders[0]
    result_folder = working_folders[1]
    change_folder(start_folder, main_folder)
    logger = start_logging()

    # start the query, process the api results, generate a Dataframe
    start_search = shodan_search(SEARCH_QUERY)

    # Check if we have some results to work with first.
    if start_search:
        search_processed = process_results(start_search)
        new_df = pd.DataFrame(search_processed)
        new_df.head(1)

    # There are no results to work with. We're creating an empty dataframe
    # storing it as csv and exiting the script.
    else:
        logger.info('No files found. Saving as empty.csv and exiting.')
        empty_df = create_empty_dataframe()
        change_folder(start_folder, result_folder)
        empty_df.to_csv(TIME_NOW + '_empty.csv', index=False)
        sys.exit(0)

    # Read in the results from last time's scan.
    try:
        old_df = pd.read_csv('old_df.csv')
    except FileNotFoundError as e:
        logger.info('File not found, creating empty dataframe.')
        old_df = create_empty_dataframe()

    # an emtpy dataframe, that we're going to populate with our new findings
    query_df = create_empty_dataframe()
    logger.debug('Empty database "query_df" created.')
    check_results = compare_dataframes(new_df, old_df)

    if isinstance(check_results, pd.DataFrame):
        for index, row in check_results.iterrows():
            logger.debug('There are new results: {}'.format(row['ip_str']))

    else:
        logger.debug('There are no new findings.')

    # we're saving the new results in a timestamped-file
    change_folder(start_folder, result_folder)
    new_df.to_csv(TIME_NOW + '_results.csv', index=False)

    # next time around, we want to work with our new results
    # since we're opening up 'old_df.csv' at the beginning of
    # the script, we have to save our new results as "old_df.csv"
    old_df = new_df
    change_folder(start_folder, main_folder)
    old_df.to_csv('old_df.csv', index=False)
