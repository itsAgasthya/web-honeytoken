import requests

ABUSEIPDB_API_KEY = "aa0ed8e5f267e7b8853310efe79604db23643fd7ecdc3e1afec6d2f78f2735050c5ec37d8c92b21c"

response = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
    params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
)

print(response.json())
