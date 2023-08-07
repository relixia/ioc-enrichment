# ioc-enrichment
Indicator of Comprimise enrichment service which uses 22+ services alltogether.
Possible ioc types to be analyzed:
  URL
  Domain
  IP Address
  Email Address
  File Hash
  File (via uploading directly)

For the python libraries; Poetry, Celery, Redis, Rabbitmq, SqlAlchemy, Psycopg2, FastAPI, Dynaconf with .env, jinja2, and requests are used.

The service can be started directly with "docker compose up" function.
Then, go to http://localhost:8000 in your favorite browser to use the service. When a possible ioc is submitted. you redirected to http://localhost:8000/search endpoint and results can be seen by navigating through the website and service buttons. 

Here is http://localhost:8000/
<img width="1470" alt="main page" src="https://github.com/relixia/ioc-enrichment/assets/77904399/aaba5fe9-63a8-44fc-9a74-b2748e93db58">

Here is loading process:
<img width="1470" alt="loading process" src="https://github.com/relixia/ioc-enrichment/assets/77904399/17880beb-ca4a-4519-9241-cc4454ecc8bc">

Here is http://localhost:8000/search:
<img width="1470" alt="result page" src="https://github.com/relixia/ioc-enrichment/assets/77904399/4238982d-f4c3-4671-9e7f-ba1ce5d594bc">



