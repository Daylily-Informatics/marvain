#!/usr/bin/env python3
"""Write commit message and run git commit."""
import subprocess, os
os.chdir("/Users/jmajor/projects/daylily/marvain")

msg_path = "/Users/jmajor/projects/daylily/marvain/.git/COMMIT_MSG"
with open(msg_path, "w") as f:
    f.write("refactor: remove deprecated remotes + fix WS auth + fix SQL splitter\n")
    f.write("\n")
    f.write("Remove deprecated remotes:\n")
    f.write("- Delete sql/003_remotes.sql, sql/007_remotes_to_devices.sql\n")
    f.write("- Delete functions/hub_api/templates/remotes.html\n")
    f.write("- Remove all /api/remotes/* endpoints from app.py (541 lines)\n")
    f.write("- Remove remotes GUI route, nav link, dashboard section\n")
    f.write("- Remove TestRemotesGui and related tests (178+ lines)\n")
    f.write("- Remove unused imports: generate_device_token, hash_token\n")
    f.write("- Update SQL comments to remove remotes references\n")
    f.write("- Update 5 documentation files to reflect devices-only model\n")
    f.write("\n")
    f.write("Fix WS auth crash (DynamoDB reserved keyword):\n")
    f.write("- handler.py user auth path used bare ttl in UpdateExpression\n")
    f.write("- DynamoDB rejects this: ttl is a reserved keyword\n")
    f.write("- Fix: alias as #ttl in ExpressionAttributeNames (matches device auth path)\n")
    f.write("\n")
    f.write("Fix SQL splitter for DO $$ blocks:\n")
    f.write("- _split_sql() in ops.py now tracks dollar-quoted block state\n")
    f.write("- Prevents splitting PL/pgSQL blocks at internal semicolons\n")
    f.write("\n")
    f.write("Add .marvain-*.pid to .gitignore\n")
    f.write("\n")
    f.write("Tests: 326 passed, 15 skipped, 0 failures\n")
    f.write("Ruff: All checks passed\n")

print("Commit message written")

# Stage all and commit
subprocess.run(["git", "add", "-A"], check=True)
result = subprocess.run(["git", "commit", "-F", msg_path], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print("STDERR:", result.stderr)
else:
    print("Commit successful")

