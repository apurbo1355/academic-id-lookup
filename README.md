# Academic Team ID Lookup (BdMO 2026)

Static lookup page: enter an email, mobile number or full name and get back only the **name and ID**.

## Privacy
`data.json` contains **no raw emails, phone numbers or names**. Each lookup value is run through
PBKDF2-SHA256 (150k iterations, random salt): part of the result is the lookup key, the rest is an
AES-GCM key that decrypts that one record (`{name, id}`). A visitor can only see a record if they
already know that person's exact email, number or full name.

## Updating the data
Run `python3 scripts/build.py sheet.csv data.json excluded_ids.txt`
(`excluded_ids.txt` = one ID per line for red-marked rows that must not be searchable) on a fresh CSV export of the sheet and commit the new `data.json`.
