## cert_chain_fetcher.py

### Create the certificate chain JSON file
```sh
$ python3 cert_chain_fetcher.py  --help
usage: cert_chain_fetcher.py [-h] [--hosts HOSTS] [--port PORT] [--output OUTPUT]

Fetches the certificate chain for the given domains

options:
  -h, --help       show this help message and exit
  --hosts HOSTS
  --port PORT
  --output OUTPUT
```
```sh
$ python3 cert_chain_fetcher.py --hosts top_100_domains.txt --output cert-tree-data.json
...
$ head cert-tree-data.json
{
    "children": [
        {
            "children": [
                {
                    "children": [
                        {
                            "children": [],
                            "id": "*.google.com",
                            "properties": {
```

### Vizualize the certificate tree
```sh
$ python3 -m http.server
# Leaving the server running in background, nagivate to
# http://localhost:8000
# on a browser of your choice (e.g. firefox)
```
