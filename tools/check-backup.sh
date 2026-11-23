#!/usr/bin/env bash
# Verify a vault bucket's current contents match its latest backup snapshot, by ETag (content), not time.
# Read-only: it only reads ETags, it never changes anything.
#
# Usage (AWS creds from your environment / AWS_PROFILE as usual):
#   BUCKET=my-vaults bash tools/check-backup.sh
#   BUCKET=my-vaults BACKUP_BUCKET=my-vaults-backup AWS_PROFILE=prod bash tools/check-backup.sh
#
#   BUCKET          the vault bucket (required)
#   BACKUP_BUCKET   the backup bucket (default: ${BUCKET}-backup)
set -euo pipefail

# --- option A: hardcode here (uncomment and fill in your own values) ---
# BUCKET=my-vaults
# BACKUP_BUCKET=my-vaults-backup
# export AWS_PROFILE=my-profile
# --- option B: pass them on the command line (see usage above); leave the block above commented ---

: "${BUCKET:?set BUCKET=<vault bucket name> (or hardcode it above)}"
BACKUP_BUCKET="${BACKUP_BUCKET:-${BUCKET}-backup}"

# the newest snapshot folder in the backup bucket (each has a manifest.json listing every object's ETag)
SNAP=$(aws s3api list-objects-v2 --bucket "$BACKUP_BUCKET" --query "Contents[].Key" --output text \
       | tr '\t' '\n' | grep manifest.json | sed 's#/manifest.json##' | sort | tail -1)
[ -n "$SNAP" ] || { echo "no snapshot (manifest.json) found in $BACKUP_BUCKET"; exit 1; }
echo "baseline snapshot: $SNAP"
echo

aws s3 cp "s3://$BACKUP_BUCKET/$SNAP/manifest.json" - \
 | BUCKET="$BUCKET" python3 -c '
import sys, os, json, subprocess
bucket = os.environ["BUCKET"]
objects = json.load(sys.stdin)["objects"]
changed = 0
for key, want in objects.items():
    want = want.strip(chr(34))
    try:
        now = subprocess.check_output(
            ["aws", "s3api", "head-object", "--bucket", bucket, "--key", key, "--query", "ETag", "--output", "text"],
            stderr=subprocess.DEVNULL).decode().strip().strip(chr(34))
    except subprocess.CalledProcessError:
        now = ""
    if now == want:
        print("OK    " + key)
    else:
        print("DIFF  " + key + "  (now: " + (now or "missing/deleted") + ")")
        changed += 1
print()
print("All match — nothing changed." if changed == 0 else str(changed) + " changed — restore from the snapshot.")
'
