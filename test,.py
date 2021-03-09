import tika
tika.initVM()
from tika import parser
parsed = parser.from_file('/Users/yifengshi/Documents/DSCI550_homeworks/tika-img-similarity/email_content_data_separate/email_content_1.txt')
print(parsed['metadata'])
print(parsed['content'])