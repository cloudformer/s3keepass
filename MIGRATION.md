# Moving off s3keepass

s3keepass keeps nothing proprietary: each vault is a standard KeePass file. Leaving is a download.

1. Open the UI, and for each vault click ⤓ (or `aws s3 cp s3://<bucket>/keepass/ . --recursive`).
2. Open the `.kdbx` in KeePassXC, KeePass, KeeWeb, Strongbox or KeePassDX with the same master password, or import
   it into another password manager (most import KeePass files or KeePassXC's CSV export).
3. Delete the stack: `terraform -chdir=terraform destroy -var-file=s3keepass.json` (set `"force_destroy": true`
   first if the bucket still holds vaults and versions you no longer need).

What you gain elsewhere: sharing and permissions for a team, browser autofill, key-file / hardware-key unlock.
What you lose: your vaults in your own bucket, versioned, at ≈ $0.
