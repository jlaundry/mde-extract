# mde-extract

A simple Python script to extract the Device telemetry via the Graph API.

## Setup

Create an Entra App Registration, with the **Application** permission for Microsoft Graph `ThreatHunting.Read.All` consented. Note the tenant ID, application (client) ID, and client secret.

## Usage

Set the client secret in your environment, with something like:

```bash
echo -n "CLIENT_SECRET: " && IFS= read -rs CLIENT_SECRET && export CLIENT_SECRET
```

Then, following the instructions:

```
usage: Extract telemetry from Defender for Endpoint [-h] [--client_secret CLIENT_SECRET] [-d DEVICE_IDS [DEVICE_IDS ...]] [-t TABLES [TABLES ...]] [--hours-ago HOURS_AGO] tenant_id client_id

positional arguments:
  tenant_id             The Entra tenant GUID/domain (contoso.onmicrosoft.com)
  client_id             The Entra App Registration Application (Client) ID

options:
  -h, --help            show this help message and exit
  --client_secret CLIENT_SECRET
                        The Entra App Registration secret (if not set, will use the CLIENT_SECRET env var)
  -d DEVICE_IDS [DEVICE_IDS ...], --device_ids DEVICE_IDS [DEVICE_IDS ...]
                        DeviceId(s) to extract (leave blank for all)
  -t TABLES [TABLES ...], --tables TABLES [TABLES ...]
                        The tables to extract from (leave blank for `union Device*`)
  --hours-ago HOURS_AGO
                        How many hours to look back (defaults to 24)
```

So for example: `python3 main.py {tenant_id} {client_id} -d aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hours-ago 24`
