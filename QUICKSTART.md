# QUICKSTART (nuke + reinstall + run)

This is the “delete everything and start from scratch” workflow for **marvain**.

> Safety: these steps can delete AWS resources and local state. Read once before running.

## Assumptions

- Repo root: you are in the `marvain/` directory.
- You have an AWS profile/region to use (examples below use `daylily` + `us-west-2`).
- You are OK deleting the CloudFormation stack for your chosen `stack_name`.

## What “delete everything” means (important)

- `marvain teardown` deletes the **CloudFormation stack**.
- This repo’s SAM template marks **both buckets as Retain**:
  - `ArtifactBucket` (Retain)
  - `AuditBucket` (Retain + **S3 Object Lock**, default 10-year governance retention)

So: **stack deletion will NOT delete those buckets**. If you put objects in the audit bucket, deleting them may be blocked by Object Lock.

## 1) Delete everything in AWS (stack + best-effort buckets)

### 1.1 Capture bucket names before teardown

You’ll need these if you want to attempt bucket deletion later.

<augment_code_snippet mode="EXCERPT">
````sh
. ./marvain_activate
./bin/marvain --profile daylily --region us-west-2 monitor outputs
# optional: also write outputs into your config
./bin/marvain --profile daylily --region us-west-2 monitor outputs --write-config
````
</augment_code_snippet>

Look for `ArtifactBucketName` and `AuditBucketName` in the printed JSON.

### 1.2 Tear down the stack

<augment_code_snippet mode="EXCERPT">
````sh
./bin/marvain --profile daylily --region us-west-2 teardown --yes --wait
````
</augment_code_snippet>

### 1.3 (Optional) Delete retained buckets

- **Artifact bucket**: typically deletable once empty.
- **Audit bucket**: may be **not deletable** if it contains Object-Lock-protected objects.

If you want to try anyway:

<augment_code_snippet mode="EXCERPT">
````sh
# Replace BUCKET with ArtifactBucketName or AuditBucketName from step 1.1
aws s3 rb "s3://BUCKET" --force
````
</augment_code_snippet>

If `AuditBucket` deletion fails due to Object Lock retention, the “from scratch” approach is:
- leave the audit bucket alone, and/or
- deploy a new stack name (fresh resources) instead of trying to hard-delete locked audit history.

## 2) Delete everything locally

### 2.1 Remove local config (this deletes your saved device token)

Config default path:
- `${XDG_CONFIG_HOME:-~/.config}/marvain/marvain.yaml`

If you want to keep a copy of the token/config, back it up first.

<augment_code_snippet mode="EXCERPT">
````sh
# OPTIONAL backup
cp -v "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain.yaml" \
  "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain.yaml.bak" 2>/dev/null || true

# Delete config (XDG + legacy)
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain.yaml" \
      "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/config.yaml" \
      "$HOME/.marvain/config.yaml"
````
</augment_code_snippet>

### 2.2 Remove build artifacts in the repo

<augment_code_snippet mode="EXCERPT">
````sh
rm -rf .aws-sam .aws-*
````
</augment_code_snippet>

### 2.3 Remove the Conda env

<augment_code_snippet mode="EXCERPT">
````sh
conda env remove -n marvain
````
</augment_code_snippet>

## 3) Install from scratch

### 3.1 Create env + activate

<augment_code_snippet mode="EXCERPT">
````sh
conda env create -f config/marvain_conda.yaml
. ./marvain_activate
````
</augment_code_snippet>

### 3.2 Toolchain sanity check

<augment_code_snippet mode="EXCERPT">
````sh
./bin/marvain --profile daylily --region us-west-2 doctor
````
</augment_code_snippet>

## 4) Run it (deploy + init db + bootstrap + logs + GUI)

<augment_code_snippet mode="EXCERPT">
````sh
# Create a fresh config
./bin/marvain config init --profile daylily --region us-west-2 --env dev

# Build + deploy (guided by default)
./bin/marvain build
./bin/marvain deploy

# Record outputs into config for convenience
./bin/marvain monitor outputs --write-config

# Initialize DB schema, then bootstrap your first device
./bin/marvain init db
./bin/marvain bootstrap --agent-name Forge --space-name home

# Tailing logs + open GUI
./bin/marvain logs --since 10m

# Print the deployed GUI URL (HubRestApiBase)
./bin/marvain gui
````
</augment_code_snippet>

## 5) Cleanup again (optional)

<augment_code_snippet mode="EXCERPT">
````sh
./bin/marvain --profile daylily --region us-west-2 teardown --yes --wait
````
</augment_code_snippet>

