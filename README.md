# Project Title: Enser Platform

Enser is a dynamic web platform that bridges the gap between students, professors, and the community, fostering collaboration and real-world engineering project experience.

## Description

Enser is designed to facilitate the seamless sharing, management, and grading of engineering projects. This platform connects students with real-world challenges, allowing them to collaborate with professors and community members to apply their academic knowledge in practical settings.

## Features

- **User Authentication**: Support for registration, login, and password management.
- **Role-Based Access**: Differentiated interfaces and functionalities for students, professors, and community members.
- **Project Management**: Tools for uploading, managing, and grading projects.
- **Dynamic Syllabus Generation**: Professors can generate and edit syllabi(with the help of chat gpt API) that are automatically tailored to project requirements.
- - **Dynamic Grading Generation**: Professors can generate automatic Grading Rubric to grade the student submission projects and Grading is also view to the student.
- **Community Engagement**: Community members can submit project ideas and feedback.

## System Requirements

Before installing and running the Enser platform, ensure that your system meets these requirements:

- **Python**: Python 3.8 or newer
- **MySQL**: MySQL 8.0 or newer
- **Web Browser**: Latest version of Chrome, Firefox, or Safari


##To Run The Project
- Install Python :If you do not have Python installed, download and install it from python.org.
- Set Up a Virtual Environment:To create and activate a virtual environment:
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

- CHAT GPT API Key: You need to set up API key in your Enivronment.
  For Windows:set API_KEY=your_actual_api_key_here
  For Mac:export API_KEY="your_actual_api_key_here"

-Installing Modules in The Environment:
 pip install requirements.txt
-pip install reuirement text:
Package                Version
---------------------- -----------
aiohttp                3.9.4
aiosignal              1.3.1
alembic                1.13.1
annotated-types        0.6.0
anyio                  4.3.0
app                    0.0.1
asgiref                3.7.2
attrs                  23.2.0
bcrypt                 4.1.2
blinker                1.7.0
certifi                2024.2.2
cffi                   1.16.0
chardet                5.2.0
charset-normalizer     3.3.2
click                  8.1.7
colorama               0.4.6
cors                   1.0.1
distro                 1.9.0
Django                 5.0.2
dnspython              2.6.1
email_validator        2.1.1
filelock               3.13.1
Flask                  3.0.2
Flask-Bcrypt           1.0.1
Flask-Cors             4.0.0
Flask-JWT-Extended     4.6.0
Flask-Login            0.6.3
Flask-Mail             0.9.1
Flask-Migrate          4.0.7
Flask-MySQLdb          2.0.0
Flask-SQLAlchemy       3.1.1
Flask-WTF              1.2.1
frozenlist             1.4.1
future                 1.0.0
gevent                 24.2.1
greenlet               3.0.3
h11                    0.14.0
httpcore               1.0.4
httpx                  0.27.0
idna                   3.6
itsdangerous           2.1.2
Jinja2                 3.1.3
Mako                   1.3.2
MarkupSafe             2.1.5
module-name            0.6.0
multidict              6.0.5
mysql-connector-python 8.3.0
mysqlclient            2.2.4
numpy                  1.26.4
openai                 1.23.2
panda                  0.3.1
pandas                 2.2.2
pdfkit                 1.0.0
pillow                 10.3.0
pip                    24.0
pycparser              2.21
pydantic               2.6.4
pydantic_core          2.16.3
PyJWT                  2.8.0
PyMySQL                1.1.0
PySocks                1.7.1
python-dateutil        2.9.0.post0
python-dotenv          1.0.1
pytz                   2024.1
reportlab              4.2.0
requests               2.31.0
requests-file          2.0.0
setuptools             69.2.0
six                    1.16.0
sniffio                1.3.1
SQLAlchemy             2.0.28
sqlparse               0.4.4
tldextract             5.1.2
tqdm                   4.66.2
typing_extensions      4.10.0
tzdata                 2024.1
urllib3                2.2.1
Werkzeug               3.0.1
wkhtmltopdf            0.2
WTForms                3.1.2
yarl                   1.9.4
zope.event             5.0
zope.interface         6.2


##Databae Prerequisites

Ensure that MySQL is installed on your system. If MySQL is not installed, you can download and install it from the [MySQL official website](https://dev.mysql.com/downloads/). Choose the version suitable for your operating system.

### Creating the Database

1. **Open MySQL Command Line Client**:
   - Windows: Search for MySQL Command Line Client in the start menu.
   - macOS/Linux: Open your terminal and type `mysql -u root -p`, then enter your MySQL root password.

2. **Create a New Database**:
   - Once inside MySQL, execute the following command to create a new database:
     ```sql
     CREATE DATABASE enserdb;

  


