import os
import re
import pandas
import json
import pandas as pd
import config
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from pysafebrowsing import SafeBrowsing




if __name__ == "__main__":
    part6_data_path = os.getcwd() + "/email_context_part6_complete.json"
    with open(part6_data_path, 'r') as data_out:
        part6_data=json.load(data_out)
    parent_directory = os.getcwd() + "/email_content_data_separate/"
    for k in part6_data.keys():
        print(k)
        if k == 'GDPPerCapita' or k == 'UnversityAndEduDomains' or k == 'MaliciousUrls':
            continue
        with open(parent_directory + "email_content_" + k + ".txt", "w") as email_out:
            json.dump(part6_data[k], email_out)
