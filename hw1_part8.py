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


def store_df_arr_to_csv(name, dataframe):
    '''
    store df array to text file
    '''
    dataframe[name].to_csv("%s.csv"%name,index=False)

if __name__=="__main__":
    file_path = os.getcwd() + "/email_context_part6_complete.json"
    
    with open(file_path, 'r') as out:
        hw_dict = json.load(out)
    actual_dict = {}
    for key in hw_dict.keys():
        if key == 'GDPPerCapita' or key == 'UnversityAndEduDomains' or key == 'MaliciousUrls':
            continue
        actual_dict[int(key)] = hw_dict[key]

    dataframe = pd.DataFrame.from_dict({(int(i)):actual_dict[i] for i in actual_dict.keys()}, orient='index')
    dataframe_for_extraction = dataframe[['Author','Content-Type', 'X-Parsed-By', 'X-TIKA:content',
       'X-TIKA:content_handler', 'X-TIKA:embedded_depth','Message-From','MboxParser-reply-to','Message-To','Message:Raw-Header:Reply-To',
       'X-TIKA:embedded_resource_path', 'X-TIKA:parse_time_millis',
       'isReconnaissance', 'isSocialEngineering', 'isMalware',
       'isCredentialPhishing', 'isAttackerSuperior', 'isUrgent',
       'attackerOffer', 'locations', 'relationships', 'sentiment',
       'misspellings', 'randomCaps', 'fraudScore', 'gdpPerCapitaPerCountry',
       'emailSenderAge','urls','anyUrlsInContent','numbersOfUrls','areUrlsMalicious','createdAt','isReceiverFromEduOrUniversity']]

    store_df_arr_to_csv('Author',dataframe_for_extraction['Author'])
    
    