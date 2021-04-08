# aws-looter
Loot AWS secrets, decryption keys and encrypted files from a box.

This is a wrapper for the AWS command line tool found in CTFs and lab boxes to automate the process. It only uses the AWS cli tool which should be installed on your compromised box and python3. In case that wasnt clear: YOU WILL NEED CREDENTIALS! 

This should only be useful for CTFs but remember: illegal things are illegal.

``` 
python3 aws_enum.py --help
BE SURE ABOUT YOUR CREDENTIALS SINCE THERE IS NO ERROR HANDLING!
usage: aws_enum.py [-h] --secret SECRET --access ACCESS --endpoint ENDPOINT

AWS Looter by dotPY

optional arguments:
  -h, --help           show this help message and exit
  --secret SECRET      AWS secret key
  --access ACCESS      AWS access key
  --endpoint ENDPOINT  Endpoint URL
```
