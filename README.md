# PythonBaseApi

Project base to create web Rest API with Python over Fastify framework.

---

## Use project

Some requirements are wanted on your system:

    - Python 3
    - Pip
    - Mysql Server 5.7
    - git

**WARNING** : ```cert.pem``` and ```key.pem``` are required to use SSL with ```uvicorn``` server.

**Clone the project**

```bash
$ git clone https://github.com/pantaflex44/PythonBaseApi.git
$ cd PythonBaseApi
$ rm -rf .git
$ git init
```

**Install Python environment**

```bash
$ python3 -m venv ./venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
```

**Install database and faker data**

```bash
$ python -m api --db-install
```

**Use this API as script**

```bash
$ python -m api
```

To naviguate in th API doc, use your browser at https://127.0.0.1:8443/docs#/

The default login credentials is:

    - Username: administrator
    - Password: Admin1234!

**Deployment**

The main entry point to deploy API online is: ```api:app```.

With an ```uvicorn``` server, you can use:

```bash
$ uvicorn --use-colors --reload --host 127.0.0.1 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem api:app 
```


