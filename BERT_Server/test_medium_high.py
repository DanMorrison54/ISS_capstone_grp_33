import json
import urllib.request

tests = [
    {
        "name": "Medium-risk attachment example",
        "payload": {
            "sender": "billing@example.com",
            "subject": "Your payment receipt",
            "body": "Please see the attached receipt.",
            "attachments": ["PAYMENT RECEIPT #76576.jpg"]
        }
    },
    {
        "name": "High-risk attachment example",
        "payload": {
            "sender": "security@example.com",
            "subject": "Account document",
            "body": "Please open the attached file.",
            "attachments": ["invoice.pdf.exe"]
        }
    }
]

for test in tests:
    request = urllib.request.Request(
        "http://127.0.0.1:5000/analyze",
        data=json.dumps(test["payload"]).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request) as response:
        print("\n" + test["name"])
        print(json.dumps(json.loads(response.read()), indent=2))
