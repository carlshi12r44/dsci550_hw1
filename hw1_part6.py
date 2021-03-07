import hw1
import os
import re
import pandas
import json
import pandas as pd
import config


def reformat_dict(d: dict) -> dict:
    '''
    reformat dictionary from process_csv to dictinoary with another format

    '''
    return {}


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


def process_part_6(file_path: str) -> dict:
    '''
    find url from emails content 
    ref link: https://www.geeksforgeeks.org/python-check-url-string/
    '''
    with open(file_path, "rb") as json_file:
        data = json.load(json_file)
    GDP_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"
    gdp_dict = process_gdp_csv(GDP_by_county_csv_path)

    # use regular expression to find the urls pattern
    pattern = r"/(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/"
    for key in data.keys():
        print(key)
        content = data[key]["X-TIKA:content"]
        data[key]["urls"] = re.findall(pattern, content)
        data[key]["gdpPerCapitaPerCountry"] = find_gdp_per_capita(
            gdp_dict, data[key]['locations'])

    return data


if __name__ == "__main__":
    GDP_by_county_csv_path = os.getcwd() + "\data\gdp-per-capita-worldbank.csv"

    json_file_string_context_path = os.getcwd() + "\emails_context_5b.json"
    json_data_part6_data = process_part_6(json_file_string_context_path)
    print(json_data_part6_data["7"]["gdpPerCapitaPerCountry"])
