
from datetime import datetime, timedelta, timezone
import argparse
import csv
import json
import logging
import os
import urllib3


http = urllib3.PoolManager()


class GraphLimitsError(Exception):
    pass


class GraphAPI():

    def __init__(self, tenant_domain:str, client_id:str, client_secret:str):
        self._tenant_domain = tenant_domain
        self.__token_postdata = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }
        self.__token_expiry = datetime.now() - timedelta(seconds=1)

        self.__token_postdata['scope'] = "https://graph.microsoft.com/.default"

    @property
    def _token(self):
        # TODO refresh token?
        if self.__token_expiry < datetime.now():
            self.__login()
        return self.__token
    
    def __login(self):

        login_timestamp = datetime.now()

        token_url = f"https://login.microsoftonline.com/{self._tenant_domain}/oauth2/v2.0/token"

        r = http.request("POST", token_url, fields=self.__token_postdata)

        if r.status in [200, 201]:
            result = json.loads(r.data.decode('utf-8'))
            expires_in = result['expires_in']
            if type(expires_in) is str:
                expires_in = int(expires_in)
            expires_in = expires_in - 60
            self.__token_expiry = login_timestamp + timedelta(seconds=expires_in)
            self.__token = result['access_token']

        else:
            raise Exception(f"Failed to get Access Token ({r.status}): {r.data}")
    
    def _run_advanced_hunting_query(self, query:str):
        url = "https://graph.microsoft.com/beta/security/runHuntingQuery"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

        body = {
            "Query": query
        }

        r = http.request("POST",
            url,
            headers=headers,
            body=json.dumps(body)
        )

        try:
            result = json.loads(r.data.decode('utf-8'))
        except json.decoder.JSONDecodeError:
            raise Exception(f"Couldn't decode r.data as JSON: {r.data}")

        # POST https://graph.microsoft.com/beta/security/runHuntingQuery returned 400:
        #   {'error': {'code': 'BadRequest', 'message': 'Query execution has exceeded the allowed limits. The query execution was preempted. This could possibly be due to high CPU and/or memory resource consumption. Optimize your query by following best practices and try again.', 'innerError': {'date': '2024-02-13T22:04:59', 'request-id': '00000000-0000-0000-0000-000000000000', 'client-request-id': '00000000-0000-0000-0000-000000000000'}}}
        if r.status == 400 and result['error']['message'].lower().startswith("Query execution has exceeded the allowed limits".lower()):
            raise GraphLimitsError()

        if r.status != 200:
            logging.warning(f"POST {url} returned {r.status}: {result}")
            return None
        
        return result

    def export_device_data(self, device_ids:list=[], tables:list=[], hours_ago:int=24):

        query = f"union {', '.join(tables)} "
        query += f"| where Timestamp >ago({hours_ago}h) "
        if len(device_ids) != 0:
            device_id_set = ', '.join([f"'{x}'" for x in device_ids])
            query += f"| where DeviceId in ({device_id_set}) "
        query += "| sort by Timestamp asc"

        print(query)

        result = self._run_advanced_hunting_query(query)

        base_file_name = "data"
        csv_headers = [x['name'] for x in result['schema']]

        with open(f"{base_file_name}.json", 'w') as of:
            json.dump(result, of, indent=4)

        with open(f"{base_file_name}.csv", 'w') as of:
            writer = csv.DictWriter(of, fieldnames=csv_headers)
            writer.writeheader()
            for row in result['results']:
                writer.writerow({k:v for (k,v) in row.items() if not k.endswith("@odata.type")})


if __name__ == '__main__':

    parser = argparse.ArgumentParser("Extract telemetry from Defender for Endpoint")

    parser.add_argument("tenant_id", help="The Entra tenant GUID/domain (contoso.onmicrosoft.com)")
    parser.add_argument("client_id", help="The Entra App Registration Application (Client) ID")
    parser.add_argument(
        "--client_secret",
        default=os.environ.get('CLIENT_SECRET'),
        help="The Entra App Registration secret (if not set, will use the CLIENT_SECRET env var)"
    )

    parser.add_argument(
        '-d',
        '--device_ids',
        nargs='+',
        default=[],
        help="DeviceId(s) to extract (leave blank for all)"
    )

    parser.add_argument(
        '-t',
        '--tables',
        nargs='+',
        default=["Device*"],
        help="The tables to extract from (leave blank for `union Device*`)"
    )

    parser.add_argument(
        "--hours-ago",
        type=int,
        default=24,
        help="How many hours to look back (defaults to 24)"
    )

    args = parser.parse_args()

    if not args.client_secret:
        exit(parser.print_usage())

    graph = GraphAPI(
        args.tenant_id,
        args.client_id,
        args.client_secret
    )

    graph.export_device_data(
        device_ids=args.device_ids,
        tables=args.tables,
        hours_ago=args.hours_ago,
    )
