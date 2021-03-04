from tika import parser
from bs4 import BeautifulSoup
from lxml import etree
from datetime import datetime
from ip2geotools.databases.noncommercial import DbIpCity
import ipaddress
import tika
import json
import os
import xml.etree.ElementTree as ET
import re

tika.initVM()

# use this to run in the command line to get the json file
# java -jar tika-app-1.25.jar -J /Users/yifengshi/Documents/USC/SP2021/DSCI550/Assignments/hw1/src/data/fradulent_emails.txt


def query(xml_string):
    '''
    query based on namespace and nodename
    you only need tree element
    '''
    soup = BeautifulSoup(xml_string, 'lxml')
    if (soup.p is None):
        return soup.body.getText()
    return soup.p.getText()


def split_big_json_into_jsons(file_path):
    '''
    split big json content based on file path
    return dict with {numeric_id, data} format
    '''

    with open(file_path, 'rb') as json_file:
        json_data = json_file.read()

    data = json.loads(json_data)

    res = {}
    for i in range(len(data)):
        # print(i)
        if (i == 0):
            continue
        # convert xml to normal string
        if ("X-TIKA:content" in data[i]):
            body_content = query(data[i]["X-TIKA:content"])
            data[i]["X-TIKA:content"] = body_content
        else:
            continue
        res[i] = data[i]
    print(len(res))
    return res


def check_if_exist(phrases_list, content, title):
    '''
    check if key phrases exist in content
    # return boolean 'True' or 'False'
    '''
    for phrase in phrases_list:
        if phrase in content or phrase in title:
            return True
    return False


def process_5a(file_path):
    '''
    search reconnaissance/social engr/malware/credential phishing based on key words/pharses
    return dict in homework 1 5a
    or we could get frequent words, find stop words online or use regular experssisons for pattern searching 
    '''
    reconnaissance_phrases = ["reply back", "click here", "keep confidential"]
    social_engr_phrases = ["your friend",
                           "urgent", "threat", "children need help"]
    malware_phrases = ["click here"]
    credential_phishing = ["ssn", "date of birth", "account number"]

    with open(file_path, "rb") as json_file:
        data = json.load(json_file)

    for key in data.keys():
        # first is all meta data, don't process it
        print(key)
        content_lowercase = data[key]["X-TIKA:content"].lower().replace('\n', ' ')

        if "dc:title" in data[key].keys():
            title_lowercase = data[key]["dc:title"].lower()
        else:
            title_lowercase = ""

        data[key]["isReconnaissance"] = check_if_exist(
            reconnaissance_phrases, content_lowercase, title_lowercase)
        data[key]["isSocialEngineering"] = check_if_exist(
            social_engr_phrases, content_lowercase, title_lowercase)
        data[key]["isMalware"] = check_if_exist(
            malware_phrases, content_lowercase, title_lowercase)
        data[key]["isCredentialPhishing"] = check_if_exist(
            credential_phishing, content_lowercase, title_lowercase)

    # with open("emails_context_5a.json", "w") as out_file:
    #     json.dump(data, out_file)

    print("5a process done, data is saved as emails_context_5a.json")
    return data


def process_time(time_str):
    '''
    process and format time
    '''
    format_str = "%m/%d/%Y (%H:%M:%S)"
    datetime_strp = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
    return datetime.strftime(datetime_strp, format_str)


def process_time_parser(time_str):
    '''
    process time parser called MboxParser-from
    '''
    string = ""
    time_strs = time_str.split(' ')
    for i in range(len(time_strs) - 1):
        string += time_strs[i + 1] + " "
    # cut the string
    string = string.strip()
    format_str = "%m/%d/%Y (%H:%M:%S)"
    datetime_strp = datetime.strptime(string, "%a %b  %d %H:%M:%S %Y")
    return datetime.strftime(datetime_strp, format_str)


def process_relationship(content, email_detail):
    '''
    process relationship based on the content and the email detail
    return relationship dict
    '''
    ans = {}
    meet_online = ["online", "from the internet", "no previous coorespondence"]
    friends = ["friend"]
    friends_of_friends = ["know somebody", ""]
    next_kins = ["next of kin.", "kin", "relatives", ]
    met_before = ["meet before"]
    claimed_to_be_superior = ["prince", "colonel", "military", "nonprofit", "royal majesty",
                              "minister", "ruler", "federal government",  "col.", "first lady", "president"]

    ans["isMeetOnline"] = check_if_exist(meet_online, content, "")
    ans["isFriend"] = check_if_exist(friends, content, "")
    ans["isFriendOfFriends"] = check_if_exist(friends_of_friends, content, "")
    ans["isKins"] = check_if_exist(next_kins, content, "")
    ans["isMetBefore"] = check_if_exist(met_before, content, "")
    ans["isClaimedToBeSuperior"] = check_if_exist(
        claimed_to_be_superior, content, "")
    return ans


def is_ip_valid_ipv4(ele):
    if ele == "172.52.42.007":
        return False
    if ele == "35.000.000.00":
        return False
    if ele == "117.52.42.007":
        return False
    if ele == "20.100.000.00":
        return False
    if ele == "044.62.177.189":
        return False
    if ele == "3.0.32.200":
        return False
    if ele == "11.000.000.00":
        return False
    l = ele.split('.')
    if len(l) != 4:
        return False

    for e in l:
        if not e.isdigit():
            return False
        if int(e) < 0 or int(e) > 255:
            return False
    return True


def process_ip(detail):
    '''
    work out for ip addresses for sender locations
    ref link: https://www.geeksforgeeks.org/extract-ip-address-from-file-using-python/
    '''
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip_list = []
    for k in detail.keys():
        if isinstance(detail[k], list):
            for ele in detail[k]:
                if isinstance(ele, str):
                    res = ip_pattern.search(ele)
                    if (res):
                        ip_list.append(res[0])
        elif isinstance(detail[k], str):
            res = ip_pattern.search(detail[k])
            if (res):
                ip_list.append(res[0])

    ans = []
    # could only check for ipv4 public IP addresses
    for ele in ip_list:
        if is_ip_valid_ipv4(ele):
            ip_address = ipaddress.ip_address(ele)
            if not ip_address.is_private:
                ans.append(ele)
    return ans


def process_locations(email_detail):
    '''
    process locations infor
    return set of json strings
    ref link https://pypi.org/project/ip2geotools/
    '''
    sender_ip_address = process_ip(email_detail)

    info_set = set()
    if (sender_ip_address):
        for ip in sender_ip_address:
            print(ip)
            if not is_ip_valid_ipv4(ip):
                continue
            # convert JSON string into json (dict in python)
            info_set.add(DbIpCity.get(ip, api_key='free').to_json())

    ans = []

    for info in info_set:
        ans.append(json.loads(info))

    return ans


def process_5b(file_path):
    '''
    process 5b 
    '''

    with open(file_path, "rb") as json_file:
        data = json.load(json_file)

    # attacker title
    attacker_titles = ["prince", "colonel", "military", "nonprofit",
                       "royal majesty", "minister", "ruler", "federal government", "kin", "relatives"]
    urgent_words_list = ["urgent", "now"]
    attackers_offerings = ["money", "offer", "dollars", "funds", ""]

    for key in data.keys():
        print(key)
        content_lowercase = data[key]["X-TIKA:content"].lower().replace('\n', ' ')
        data[key]["isAttackerSuperior"] = check_if_exist(
            attacker_titles, content_lowercase, "")
        data[key]["isUrgent"] = check_if_exist(
            urgent_words_list, content_lowercase, "")
        data[key]["attackerOffer"] = check_if_exist(
            attackers_offerings, content_lowercase, "")
        if "Creation-Date" in data[key].keys():
            data[key]["createdAt"] = process_time(data[key]["Creation-Date"])
        elif "MboxParser-from" in data[key].keys():
            data[key]["createdAt"] = process_time_parser(
                data[key]["MboxParser-from"])

        # location loop up part v
        # do this link https://towardsdatascience.com/geoparsing-with-python-c8f4c9f78940
        data[key]["Locations"] = process_locations(
            data[key])
        # relationship loop up part vi
        data[key]["relationships"] = process_relationship(
            content_lowercase, data[key])

    return data


if __name__ == "__main__":
    # execute function

    # json_file_path = os.getcwd() + "\emails_context.json"
    # json_data = split_big_json_into_jsons(json_file_path)
    # print(json_data[202]["X-TIKA:content"])

    json_file_string_context_path = os.getcwd() + "\emails_context_string.json"
    #json_data_5a = process_5a(json_file_string_context_path)
    json_file_5a_path = os.getcwd() + "\emails_context_5a.json"
    json_data_5b = process_5b(json_file_5a_path)

    print(json_data_5b["202"]["relationships"])
