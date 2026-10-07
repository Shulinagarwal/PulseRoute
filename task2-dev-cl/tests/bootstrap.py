"""Create only the unscored local administrator identity."""

import json
import os
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


endpoint = os.environ.get("AWS_ENDPOINT_URL", "http://aws:4566")
out = Path(os.environ.get("PULSEROUTE_CONFIG_DIR", "/config"))
iam = boto3.client("iam", endpoint_url=endpoint, region_name="us-east-1",
                   aws_access_key_id="111111111111", aws_secret_access_key="local-bootstrap")


def main():
    name = "pulseroute-admin"
    try:
        iam.get_user(UserName=name)
    except ClientError as error:
        if error.response["Error"]["Code"] != "NoSuchEntity":
            raise
        iam.create_user(UserName=name)
    iam.attach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
    key = iam.create_access_key(UserName=name)["AccessKey"]
    out.mkdir(parents=True, exist_ok=True)
    admin = {"access_key_id": key["AccessKeyId"], "secret_access_key": key["SecretAccessKey"]}
    (out / "bootstrap.json").write_text(json.dumps({"admin": admin}, indent=2) + "\n")
    (out / "terraform.tfvars.json").write_text(json.dumps({
        "admin_access_key": admin["access_key_id"],
        "admin_secret_key": admin["secret_access_key"],
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
