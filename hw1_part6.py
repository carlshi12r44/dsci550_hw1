import hw1
import os
import re
import pandas
import json
import pandas as pd
import config
from urllib.parse import urlparse
from pysafebrowsing import SafeBrowsing


def process_gdp_csv(file_path: str) -> dict:
    '''
    process csv to find GDP per capita by zip codes
    '''
    df = pd.read_csv(file_path)
    res_dict = df.to_dict()
    ans = {}

    for i in range(len(res_dict['Country Name'])):
        ans[res_dict['Country Name'][i]] = res_dict['2019'][i]
    return ans


def find_gdp_per_capita(gdp_dict: dict, locations_info: dict) -> int:
    '''
    find median gdp per capita per country
    -1 means no gdp per capita data found
    '''
    if locations_info:
        if locations_info[0]['country_name'] and locations_info[0]['country_name'] in gdp_dict.keys():
            return gdp_dict[locations_info[0]['country_name']]

    # zip_code = response["locations"][0][]
    return -1


def process_domain_names(domains_path: str) -> dict:
    '''
    process domain names 
    '''
    data_dict = json.loads(domains_path)
    return data_dict


def check_urls_malicious(urls_list: list) -> int:
    '''
    check if urls are malicious
    1 means malicious, 0 means not malicious, -1 means either url is not present
    '''
    url_check_server = SafeBrowsing(config.google_safe_browsing_api_key)
    if urls_list:
        url = urls_list[0][0]
        #url_domain = urlparse(url).netloc
        response = url_check_server.lookup_urls([url])
        if response[url]['malicious']:
            return 1
        else:
            return 0
    return -1


def process_part_6(file_path: str) -> dict:
    '''
    find url from emails content 
    ref link: https://www.geeksforgeeks.org/python-check-url-string/
    '''
    with open(file_path, "rb") as json_file:
        data = json.load(json_file)
    GDP_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"
    gdp_dict = process_gdp_csv(GDP_by_county_csv_path)

    domain_names_json_path = os.getcwd() + "\data\world_universities_and_domains.json"

    # use regular expression to find the urls pattern
    pattern = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    for key in data.keys():
        print(key)
        content = data[key]["X-TIKA:content"]
        data[key]["gdpPerCapitaPerCountry"] = find_gdp_per_capita(
            gdp_dict, data[key]['locations'])
        if (key == "2680"):
            continue
        data[key]["urls"] = re.findall(pattern, content)
        data[key]["areUrlsMalicious"] = check_urls_malicious(data[key]["urls"])
    return data


if __name__ == "__main__":
    GDP_by_county_csv_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"

    json_file_string_context_path = os.getcwd() + "\emails_context_5b.json"
    json_data_part6_data = process_part_6(json_file_string_context_path)
    print(json_data_part6_data["7"]["urls"][0][0])
