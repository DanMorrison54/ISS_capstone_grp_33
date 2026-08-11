import json
import urllib.request

samples = [
    {
        "name": "Phishing-style email",
        "payload": {
            "sender": "security@fake-bank.example",
            "subject": "Urgent: Verify your account immediately",
            "body": "Your account will be suspended. Sign in now and confirm your password at https://bit.ly/example.",
            "attachments": ["Account_Verification.docm"]
        }
    },
    {
        "name": "Legitimate-style email",
        "payload": {
            "sender": "professor@college.ca",
            "subject": "Thursday class meeting",
            "body": "This is a reminder that our class meeting is Thursday at 2 PM.",
            "attachments": ["course_outline.pdf"]
        }
    }
]

for sample in samples:
    request = urllib.request.Request(
        "http://127.0.0.1:5000/analyze",
        data=json.dumps(sample["payload"]).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    print("\\n" + sample["name"])
    with urllib.request.urlopen(request) as response:
        print(json.dumps(json.loads(response.read()), indent=2))
