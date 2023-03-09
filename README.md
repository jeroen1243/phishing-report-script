# Phishing report script
This project is a tool to report phishing sites to the hosting provider, registrar and multiple anti-phishing services.

## Installation with pip and virtual environment
``` bash
$ git clone https://github.com/jeroen1243/anti-phishing
$ cd anti-phishing
$ virtualenv venv
$ source venv/bin/activate # for Linux
$ .\venv\Scripts\activate # for Windows (you also might need to change te execution policy by running: $ Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
$ pip install -r requirements.txt
```
Also install the firefox gecko driver if you want the Cloudflare webform report to work. You can download it from https://github.com/mozilla/geckodriver/releases

## Configuration
The credentials and other setting are stored in a .env file. You can rename the .env.example file to .env and fill in the credentials.

## Usage
``` bash
$ python anti-phishing.py
```

