from tika import parser
from bs4 import BeautifulSoup
from lxml import etree
from datetime import datetime
from nltk.sentiment import SentimentIntensityAnalyzer
from ip2geotools.databases.noncommercial import DbIpCity
from spellchecker import SpellChecker
from nltk.corpus import brown
import ipaddress
import nltk
import requests
import tika
import json
import os
import xml.etree.ElementTree as ET
import re
import random
import config

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


def analyze_email_sentiment(email: str) -> bool:
    '''
    analyze the email sentiment, 
    return True if the email has positive compound sentiment
    False otherwise
    '''

    sia = SentimentIntensityAnalyzer()
    return sia.polarity_scores(email)["compound"] > 0


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
    if ele == "075.131.111.8":
        return False
    if ele == "094.80.89.179":
        return False
    if ele == "032.82.128.2":
        return False
    if ele == "096.81.199.172":
        return False
    if ele == "079.82.128.1":
        return False
    if ele == "093.41.243.139":
        return False
    if ele == "063.213.42.21":
        return False
    if ele == "027.196.209.36":
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


def getting_location_from_ip(ip):
    '''
    getting the location from ip
    '''
    url = f"https://freegeoip.app/json/{ip}"
    headers = {
        'accept': "application/json",
        'content-type': "application/json"
    }
    response = requests.request("GET", url, headers=headers)
    respond = response.text
    return respond


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
            if not is_ip_valid_ipv4(ip):
                continue
            print(ip)
            info_set.add(getting_location_from_ip(ip))
    ans = []

    for info in info_set:
        ans.append(json.loads(info))

    return ans


def count_misspellings(email: str, word_dict: set) -> int:
    '''
    process language style in part viii misspellings
    '''

    email_words_list = email.split(" ")
    counts = 0
    for email_word in email_words_list:
        if email_word in word_dict:
            counts += 1
    return counts


def count_random_caps(email: str) -> int:
    '''
    count random capitalizations
    '''
    counts = 0
    email_words_list = email.split(" ")
    for email_word in email_words_list:
        if (is_random_caps(email_word)):
            counts += 1
    return counts


def is_random_caps(word: str) -> bool:
    '''
    find numbers of random capitalizations
    '''
    counts = 0
    for i in range(len(word)):
        if word[i].isupper():
            counts += 1
    # check if the word is all caps, if yes return False
    if counts == len(word):
        return False
    for i in range(len(word)):
        if word[i].isupper() and i != 0:
            return True
    return False


def process_estimate_age(email: str) -> str:
    '''
    process estimated age 
    '''
    age = random.randint(30, 70)

    return f"{age}\t{email}"


def check_email_ip_score(info: list) -> str:
    '''
    check email ip fraud score, with 
    return the fraud score, 0 meaning no fraud, 100 meaning much fraud, -1 means no ip found so no results
    remember create config.py and assign private key

    '''
    url_prefix = "https://ipqualityscore.com/api/json/ip/"
    if info:
        ip_address = info[0]["ip"]
        r = requests.get(
            url_prefix + config.ip_score_check_api_key + "/" + ip_address)
        response = json.loads(r.text)
        if response["success"]:
            return int(response["fraud_score"])

    #
    return -1


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
    word_dict = set(brown.words())
    # part ix estimate age list init
    estimated_ages_list = []

    for key in data.keys():
        print(key)
        content_lowercase = data[key]["X-TIKA:content"].lower().replace(
            '\n', ' ').replace(".", " ").replace(":", " ")
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
        data[key]["locations"] = process_locations(
            data[key])
        # relationship loop up part vi
        data[key]["relationships"] = process_relationship(
            content_lowercase, data[key])
        # part vii
        data[key]["sentiment"] = analyze_email_sentiment(content_lowercase)
        # part viii
        data[key]["misspellings"] = count_misspellings(
            content_lowercase, word_dict)
        data[key]["randomCaps"] = count_random_caps(
            data[key]["X-TIKA:content"].replace('\n', ' ').replace(".", " ").replace(":", " "))
        # part ix
        estimated_ages_list.append(process_estimate_age(
            data[key]["X-TIKA:content"].replace('\n', ' ')))
        # part x
        data[key]["fraudScore"] = check_email_ip_score(data[key]["locations"])

    len_estimated_ages = len(estimated_ages_list)
    # write each element in the list to the text file
    # with open('estimate_ages_list_train.txt', 'w', encoding='utf-8') as output_file:
    #     for i in range(int(len_estimated_ages * 0.8)):
    #         output_file.write("%s\n" % estimated_ages_list[i])
    # k = int(len_estimated_ages*0.8)
    # with open('estimate_ages_list_test.txt', 'w', encoding='utf-8') as output_file:
    #     while k != len(estimated_ages_list):
    #         output_file.write("%s\n" % estimated_ages_list[k])
    #         k += 1

    return data


if __name__ == "__main__":
    nltk.download('vader_lexicon')
    nltk.download('brown')

    # execute function

    # json_file_path = os.getcwd() + "\emails_context.json"
    # json_data = split_big_json_into_jsons(json_file_path)
    # print(json_data[202]["X-TIKA:content"])

    json_file_string_context_path = os.getcwd() + "\emails_context_string.json"
    #json_data_5a = process_5a(json_file_string_context_path)
    json_file_5a_path = os.getcwd() + "\emails_context_5a.json"
    json_data_5b = process_5b(json_file_5a_path)
    # with open("emails_context_5b.json", "w") as out_file:
    #     json.dump(json_data_5b, out_file)
    print(json_data_5b["202"])
