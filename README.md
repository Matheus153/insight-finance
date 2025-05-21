
# Insight Finance

A system that carries out your financial control through daily and monthly monitoring of your entries, points out improvements that could be made and automatically generates graphs with your information.

# Banner

<div align="center">
  <img src="static/images/banner/login.png">
</div>
</br>

# Pre-condition

- Git (https://git-scm.com/)
- Python (https://www.python.org/)

# Installation

Install insight-finance with pip (Python package manager)

### Cloning a repository

```bash
  git clone https://github.com/Matheus153/insight-finance.git
```
### Go to the folder
```bash
  cd insight-finance
```
### Install requirements
```bash
  pip install -r requirements.txt
```

### Environment variables
For the app to work correctly, there must be environment variables containing sensitive information for the project to run. These variables are contained in files (.env). 

Therefore, when cloning the project, create a file called “.env” in the root of the project and fill it with the following data:

``` bash
  SECRET_KEY=key_flask_can_add_whatever_you_want
  CSRF_SECRET_KEY=create_your_own_key
  SERVER_NAME=url_of_your_application_in_production_or_write_localhost:5000
  PREFERRED_URL_SCHEME=https_to_url_or_http_to_localhost
  MAIL_USERNAME=your_email
  MAIL_PASSWORD=password_email_to_sdk
  API_KEY=key_api_firebase
  TYPE=comes_from_json_firebase_file
  PROJECT_ID=comes_from_json_firebase_file
  PRIVATE_KEY_ID=comes_from_json_firebase_file
  PRIVATE_KEY=comes_from_json_firebase_file
  CLIENT_EMAIL=comes_from_json_firebase_file
  CLIENT_ID=comes_from_json_firebase_file
  AUTH_URI=comes_from_json_firebase_file
  TOKEN_URI=comes_from_json_firebase_file
  AUTH_PROVIDER_X509_CERT_URL=comes_from_json_firebase_file
  CLIENT_X509_CERT_URL=comes_from_json_firebase_file
  UNIVERSE_DOMAIN=comes_from_json_firebase_file
  MESSAGING_SENDER_ID=available_in_firebase_project_settings
  APP_ID=available_in_firebase_project_settings
  SQLALCHEMY_DATABASE_URI=database_url
```

### Where can I get this information?

#### 1. For e-mail variables:

🔐 Step: Create an App Password in Gmail

Note: You must first create or already have an email address available

Gmail no longer allows the use of normal passwords for third-party applications. You need to generate an application password:

Access: **[Conta Google](https://myaccount.google.com/security)**

- Activate Two-Step Verification (if you haven't already)

- Under Application passwords, click on “Select application” → “Other (Custom name)”

- Enter a name (e.g. “Flask App”) and click on “Generate”.

- Copy the generated 16-character password (use it in MAIL_PASSWORD)

#### 2. For Firebase variables

🔑 Step: Get the Firebase API Key

Note: First you must create or already have a project in the firebase console

- Access Firebase **[Console](https://console.firebase.google.com/)**

- In the project, click on ⚙️ > Project settings

- Under Your applications, select the web application

- Copy the API Key (appears as apiKey in config)

- Paste in the variable (“API_KEY” from the .env file)

- In the project settings go to the “Your applications” section 

- Copy and paste the values of 'messagingSenderId' and 'appId' into the environment variables (MESSAGING_SENDER_ID, APP_ID)

#### 3. Firebase Admin SDK

🔧 How to correctly generate the Firebase Admin SDK:

Access Firebase **[Console](https://console.firebase.google.com/)**

- Select your project

- Go to ⚙️ > Project settings > Service accounts

- Scroll down and click Generate new private key

- Download the .json file and fill in the environment variables in the .env file

#### 4. Configuring Firestore

🏦 To fully utilize the application's functionality, configure the Firebase database called Firestore:
Access Firebase **[Console](https://console.firebase.google.com/)**

Note: to use this feature, enable the billing option for your Google account.

- Access the "Firestore Database" tab

- Enable Cloud Firestore

- Create your database

- When creating your database, go to "Rules" and replace the current code with the following:

```bash
rules_version = '2';

service cloud.firestore {
  match /databases/{database}/documents {
    match /usuarios/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
      allow write: if false;
    }
  }
}
```

- Publish your changes

#### 5. PostgreSQL database

Note: You must first have a database created in the **[Supabase](https://supabase.com/)** or any other that is available for free (Heroku or Railway)

🏦 Configuring the database:

- Add a table called “category” to the database with the following columns:

  - **nome** (type: text)
  - **tipo** (type: text)

You can fill them in with the following pattern:

```bash
        {'nome': 'Salary', 'tipo': 'revenue'},
        {'nome': 'Investments', 'tipo': 'revenue'},
        {'nome': 'Food', 'tipo': 'expense'},
        {'nome': 'Housing', 'tipo': 'expense'},
        {'nome': 'Transport', 'tipo': 'expense'},
        {'nome': 'Leisure', 'tipo': 'expense'},
        {'nome': 'Health', 'tipo': 'expense'},
        {'nome': 'Education', 'tipo': 'expense'},
        {'nome': 'Taxes', 'tipo': 'expense'},
        {'nome': 'Pets', 'tipo': 'expense'},
        {'nome': 'Credit card', 'tipo': 'expense'},
        {'nome': 'Food voucher', 'tipo': 'revenue'},
        {'nome': 'Meal voucher', 'tipo': 'revenue'},
```

- Add a table called “transaction” to the database with the following columns:

  - **descricao** (type: text)
  - **valor** (type: float8)
  - **data** (type: timestamp)
  - **tipo** (type: text)
  - **user_id** (type: text)
  - **categoria_id** (type: int8, foreign-key: categoria.id)
  - **recorrente** (type: bool)
  - **meses_repeticao** (type: int8)
  - **data_original** (type: timestamp)

- Click on “Connect” and copy the link to the “transaction pooler” url and paste it into the environment variable (SQLALCHEMY_DATABASE_URI)

Example url:
```bash
postgresql+psycopg2://financas_app:NovaSenhaSuperSegura@localhost:5432/financas
```


## Start Server

To start the test, run the following command

```bash
  python run.py
```

## 🚀 Tech Stack

### 🧠 Backend

- **[Python](https://www.python.org/)** – the main language of the project.
- **[Flask](https://flask.palletsprojects.com/)** – microframework for creating the web application and API.
- **[Flask-RESTful](https://flask-restful.readthedocs.io/en/latest/)** – structuring RESTful routes.
- **[SQLAlchemy](https://www.sqlalchemy.org/)** – ORM for manipulating the database.

### 🖥️ Frontend (Provisório)

- **HTML5, CSS3, JavaScript**
- **Jinja2** – template engine integrated with Flask.

### 🗄️ Banco de Dados

- **[PostgreSQL](https://www.postgresql.org/)** – recomendado para produção.
- **[SQLite](https://www.sqlite.org/index.html)** – lightweight option for local development and testing.

### 📁 Project directory structure

```arduino
flask-financas/
├── app/
│   ├── __init__.py
│   ├── models.py
│   └── routes.py
├── templates/
│   ├── adicionar.html
│   ├── admin.html
│   ├── base.html
│   ├── cadastrar.html
│   ├── editar.html
│   ├── email_alerta.html
│   ├── email_recuperacao_senha.html
│   ├── index.html
│   ├── login.html
│   ├── perfil.html
│   ├── politica_privacidade.html
│   ├── recorrentes.html
│   ├── recuperar_senha.html
│   ├── redefinir_senha.html
│   ├── resumo.html
│   ├── termos_condicoes.html
│   ├── transacoes.html
│   └── tutorial.html
├── static/
│   ├── images/
│   │   └── favicon.ico
│   └── style.css
└── run.py
```

