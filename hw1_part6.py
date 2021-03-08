import hw1
import os
import re
import pandas
import json
import pandas as pd
import config
from bs4 import BeautifulSoup
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


def process_malious_html(html_path: str) -> set:
    '''
    process literal rate xml
    '''
    soup = BeautifulSoup(open(html_path), "html.parser")
    html_body = soup.find("pre").text.split("\n")
    i = 3
    ans_list = []
    while i < len(html_body):
        ans_list.append(html_body[i])
        i += 1

    return set(ans_list)


def process_domain_names(domains_path: str) -> dict:
    '''
    process domain names
    '''
    with open(domains_path, "rb") as out:
        data = json.load(out)
    return data


def check_urls_malicious(urls_list: list, malicious_set: set) -> int:
    '''
    check if urls are malicious
    1 means malicious, 0 means not malicious, -1 means either url is not present
    '''
    url_check_server = SafeBrowsing(config.google_safe_browsing_api_key)
    if urls_list:
        url = urls_list[0][0]
        # url_domain = urlparse(url).netloc
        response = url_check_server.lookup_urls([url])
        if response[url]['malicious'] or url in malicious_set:
            return 1
        else:
            return 0
    return -1


def check_receiver_from_uni_or_edu(uni_list: list, receiver_email) -> bool:
    '''
    check if receiver from university org or nams edu orga
    '''
    # regular expression for email pattern
    regex_pattern = "/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/"
    email = ""
    if isinstance(receiver_email, list):
        if not re.fullmatch(regex_pattern, receiver_email[0]):
            return False
        email = receiver_email[0]
    else:
        if not re.fullmatch(regex_pattern, receiver_email):
            return False
        email = receiver_email
    receiver_domain = email.split("@")[1]
    if "." in receiver_domain:
        receiver_suffix = receiver_domain.split(".")[1]
    else:
        return False
    if receiver_suffix == 'edu':
        return True
    for i in range(len(uni_list)):
        for d in uni_list[i]['domains']:
            if d == receiver_domain:
                return True
    return False


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
    uni_domains_dict = process_domain_names(domain_names_json_path)
    # malicious urls dict
    malicious_urls_xml_path = os.getcwd() + "\data\malicious_urls.html"
    malicious_dict = process_malious_html(malicious_urls_xml_path)

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
        if (len(data[key]["urls"]) == 0):
            data[key]["anyUrlsInContent"] = False
            data[key]["numbersOfUrls"] = 0
        else:
            data[key]["anyUrlsInContent"] = True
            data[key]["numbersOfUrls"] = len(data[key]["urls"])
        # if urls are malicious
        data[key]["areUrlsMalicious"] = check_urls_malicious(
            data[key]["urls"], malicious_dict)
        # check if receiver email belongs to university or education organizations
        if "MboxParser-reply-to" in list(data[key].keys()) and data[key]["MboxParser-reply-to"]:
            data[key]["isReceiverFromEduOrUniversity"] = check_receiver_from_uni_or_edu(uni_domains_dict,
                                                                                        data[key]["MboxParser-reply-to"])
        elif "Message-To" in list(data[key].keys()) and data[key]["Message-To"]:
            data[key]["isReceiverFromEduOrUniversity"] = check_receiver_from_uni_or_edu(uni_domains_dict,
                                                                                        data[key]["Message-To"])
        elif "Message:Raw-Header:Reply-To" in list(data[key].keys()) and data[key]["Message:Raw-Header:Reply-To"]:
            data[key]["isReceiverFromEduOrUniversity"] = check_receiver_from_uni_or_edu(uni_domains_dict,
                                                                                        data[key]["Message:Raw-Header:Reply-To"])
    data["GDPPerCapita"] = gdp_dict
    data["UnversityAndEduDomains"] = uni_domains_dict
    data["MaliciousUrls"] = malicious_dict
    return data


if __name__ == "__main__":
    GDP_by_county_csv_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"
    gdp_dict = process_gdp_csv(GDP_by_county_csv_path)
    domain_names_json_path = os.getcwd() + "\data\world_universities_and_domains.json"
    domain_dict = process_domain_names(domain_names_json_path)

    json_file_string_context_path = os.getcwd() + "\emails_context_5b.json"
    json_data_part6_data = process_part_6(json_file_string_context_path)

    # malicious_urls_xml_path = os.getcwd() + "\data\malicious_urls.html"
    # malicious_dict = process_malious_html(malicious_urls_xml_path)
    # print(json_data_part6_data["7"]["urls"][0][0])
