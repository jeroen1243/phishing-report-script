# Phishing report script
This project is a tool to report phishing sites to the hosting provider, registrar and multiple anti-phishing services.

## Installation with pip and virtual environment
``` bash
$ git clone https://github.com/jeroen1243/anti-phishing
$ cd anti-phishing
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

## Configuration
The credentials and other setting are stored in a .env file. You can rename the .env.example file to .env and fill in the credentials.

## Usage
``` bash
$ python anti-phishing.py
```

