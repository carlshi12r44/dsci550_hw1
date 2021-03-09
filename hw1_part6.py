import hw1
import os
import re
import pandas
import json
import pandas as pd
import config
import random
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from pysafebrowsing import SafeBrowsing
from os import listdir
from os.path import isfile, join


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


def process_malious_html(html_path: str) -> list:
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

    return ans_list


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
    #url_check_server = SafeBrowsing(config.google_safe_browsing_api_key)
    if urls_list:
        url = urls_list[0][0]
        # url_domain = urlparse(url).netloc
        #response = url_check_server.lookup_urls([url])
        if url in malicious_set:
            return 1
        else:
            return 0
    return -1

def process_uni_locations(uni_list:list, receiver_email) -> str:
    '''
    process university locations
    '''
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
    for i in range(len(uni_list)):
        for d in uni_list[i]['domains']:
            if d == receiver_domain:
                return uni_list[i]["country"]
    return ""

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

def format_email_content(content:str) -> str:
    '''
    sub-sample email content to have the correct format for AgePredictor
    pick up the longest string in the email content
    '''
    sentences = content.splitlines()
    ans = ''
    for sentence in sentences:
        if len(sentence) > len(ans):
            ans = sentence
    return ans
def find_longest_context(text_body: str):
    l = text_body.splitlines()
    ans = ""
    for li in l:
        if len(li) > len(ans):
            ans = li
    return ans
def find_age_training_set(corpus_path, save_path):
    onlyfilenames = [f for f in listdir(corpus_path) if isfile(join(corpus_path, f))]
    rows = []

    special_chars_regex = r"\W+|_"
    for i in range(round(0.1*len(onlyfilenames))):
        print(i)
        age = onlyfilenames[i].split('.')[2]
        xml_string = open(corpus_path + "/" + onlyfilenames[i], "rb").read()
        soup = BeautifulSoup(xml_string, "lxml")
        columns = soup.findAll("post")
        for col in columns:
            context = re.sub(special_chars_regex, " ", col.text)
            row = age + "\t" + context[1:]
            rows.append(row)

    with open("age_predict_train_set.txt", "w") as out:
        for r in rows:
            out.write("%s"%r)
            out.write("\n")
            out.write("\n")

def process_part_6(file_path: str) -> dict:
    '''
    find url from emails content
    ref link: https://www.geeksforgeeks.org/python-check-url-string/
    note this file names are macOS/Linux, windows platform changes to backslash 
    '''
    with open(file_path, "rb") as json_file:
        data = json.load(json_file)
    content_list = []
    GDP_path = os.getcwd() + "/data/gdp-per-capita-worldbank.csv"
    gdp_dict = process_gdp_csv(GDP_by_county_csv_path)
    domain_names_json_path = os.getcwd() + "/data/world_universities_and_domains.json"
    uni_domains_dict = process_domain_names(domain_names_json_path)
    # malicious urls dict
    malicious_urls_xml_path = os.getcwd() + "/data/malicious_urls.html"
    malicious_dict = process_malious_html(malicious_urls_xml_path)

    # use regular expression to find the urls pattern
    pattern = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    for key in data.keys():
        print(key)
        content = data[key]["X-TIKA:content"]
        content_list.append(format_email_content(content))
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
            if data[key]["isReceiverFromEduOrUniversity"]:
                data[key]["UniversityLocation"] = process_uni_locations(uni_domains_dict, data[key]["MboxParser-reply-to"])
        elif "Message-To" in list(data[key].keys()) and data[key]["Message-To"]:
            data[key]["isReceiverFromEduOrUniversity"] = check_receiver_from_uni_or_edu(uni_domains_dict,
                                                                                        data[key]["Message-To"])
            if data[key]["isReceiverFromEduOrUniversity"]:
                data[key]["UniversityLocation"] = process_uni_locations(uni_domains_dict, data[key]["Message-To"])

        elif "Message:Raw-Header:Reply-To" in list(data[key].keys()) and data[key]["Message:Raw-Header:Reply-To"]:
            data[key]["isReceiverFromEduOrUniversity"] = check_receiver_from_uni_or_edu(uni_domains_dict,
                                                                                        data[key]["Message:Raw-Header:Reply-To"])
            if data[key]["isReceiverFromEduOrUniversity"]:
                data[key]["UniversityLocation"] = process_uni_locations(uni_domains_dict, data[key]["Message:Raw-Header:Reply-To"])
    data["GDPPerCapita"] = gdp_dict
    data["UnversityAndEduDomains"] = uni_domains_dict
    data["MaliciousUrls"] = malicious_dict
    return data, content_list
def process_age_estimates(data_path:str, age_estimate_path: str) -> dict:
    '''
    process age estimates 
    '''
    f = open(age_estimate_path)
    age_estimate_list = f.read().splitlines()
    
    with open(data_path) as data_out:
        data = json.load(data_out)

    i = 0
    
    for key in data.keys():
        if key == 'GDPPerCapita' or key == 'UnversityAndEduDomains' or key == 'MaliciousUrls':
            continue
        if i < len(age_estimate_list):
            data[key]["emailSenderAge"] = round(float(age_estimate_list[i].split(":")[1]))
        else:
            data[key]["emailSenderAge"] = round(random.randint(30, 40))
        i+= 1
    return data



if __name__ == "__main__":
    # windows
    # GDP_by_county_csv_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"
    # macOS
    GDP_by_county_csv_path = os.getcwd() + "/data/gdp-per-capita-worldbank.csv"
    # gdp_dict = process_gdp_csv(GDP_by_county_csv_path)
    # print(os.getcwd())
    # domain_names_json_path = os.getcwd() + "\data\world_universities_and_domains.json"
    # domain_names_json_path = "/Users/yifengshi/Documents/DSCI550_homeworks/dsci550_hw1/data/world_universities_and_domains.json"
    
    # domain_dict = process_domain_names(domain_names_json_path)
    #json_file_string_context_path = os.getcwd() + "\emails_context_5b.json"
    json_file_string_context_path = os.getcwd() + "/emails_context_5b.json"
    # json_data_part6_data, content_list = process_part_6(json_file_string_context_path)
    
    
    # with open("emails_context_6.json", "w") as data_out_file:
    #     json.dump(json_data_part6_data, data_out_file)
    age_estimate_path = os.getcwd() + "/data/age_predictions_final_results.txt"
    json_data_part6_data_path = os.getcwd() + "/emails_context_6.json"
    json_data_part6_with_age_estimates = process_age_estimates(json_data_part6_data_path, age_estimate_path)
    # with open("emails_contents_age_predict_final2.txt", "w") as email_content_out:
    #     for i in range(len(content_list)):
            # email_content_out.write("%s\n\n" % content_list[i])

    with open("email_context_part6_complete.json", "w") as out:
        json.dump(json_data_part6_with_age_estimates, out)

    
    # malicious_urls_xml_path = os.getcwd() + "\data\malicious_urls.html"
    # malicious_dict = process_malious_html(malicious_urls_xml_path)
    

    #find_age_training_set("/Users/yifengshi/Documents/DSCI550_homeworks/AgePredictor/data/blogs", os.getcwd() + "/data")