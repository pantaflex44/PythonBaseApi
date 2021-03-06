# PythonBaseApi v1.1

![GitHub issues](https://img.shields.io/github/issues/pantaflex44/PythonBaseApi)
![GitHub last commit](https://img.shields.io/github/last-commit/pantaflex44/PythonBaseApi)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/pantaflex44/PythonBaseApi)
![GitHub license](https://img.shields.io/github/license/pantaflex44/PythonBaseApi)
![GitHub stars](https://img.shields.io/github/stars/pantaflex44/PythonBaseApi)
![GitHub forks](https://img.shields.io/github/forks/pantaflex44/PythonBaseApi)

Project base to create web Rest API with Python over FastAPI framework.

---

## Use project

Some requirements are wanted on your system:

    - Python 3
    - Pip 3
    - Mysql Server 5.7
    - git

**WARNING** : ```cert.pem``` and ```key.pem``` are required to use SSL with ```uvicorn``` server.


<br/>

<hr />

### Automated installation

<br />

**Download the latest PythonBaseApi installer**

```bash
$ wget https://raw.githubusercontent.com/pantaflex44/PythonBaseApi/v1/pba-latest-installer.sh
$ chmod +x pba-latest-installer.sh
```

<br />

**Then, run the installer**

```bash
$ ./pba-latest-installer.sh
```

Your done! Enjoy with your new API project!


<br />
<hr />

### Manual installation

<br />

**Clone the project**

```bash
$ git clone https://github.com/pantaflex44/PythonBaseApi.git
$ cd PythonBaseApi
$ rm -rf .git
$ git init
```

<br/>

**Install Python environment**

```bash
$ python3 -m venv ./venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```

<br/>

**Install database and faker data**

```bash
$ python3 -m api --db-install
```

<br/>

**Set personnal parameters**

All parameters found in ```core\settings.py```

To generate new JWT secret key:

```bash
$ python -m api --generate-jwt-secret
```

<br/>

**Use this API as script**

```bash
$ python -m api
```

To naviguate in the API doc, use your browser at https://127.0.0.1:8443/latest/docs

The default credentials is:

    - Username: administrator
    - Password: Admin1234!

<br/>

**Deployment**

The main entry point to deploy API online is: ```api:app```.

With an ```uvicorn``` server, you can use:

```bash
$ uvicorn --use-colors --reload --host 127.0.0.1 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem api:app 
```


