Set up cloud infrastructure for **PulseRoute**, an order-event pipeline running in a local AWS account. Each event that is published should make it to the right consumers, each consumer maintains their own delivery log, and the failed deliveries need to be recoverable while not losing successful deliveries. All messages are encrypted with a key held by the deployment and all principals receive just the level of access that AWS requires for their role; no one else, not even the administrator, can use that key. However, the deployment needs to take care of itself too, where it should fix any drift, delete any access created outside your configuration, and continue functioning even if its local Terraform state is deleted or damaged.

The app is provided in pre-packaged container images for four services:

1. The **Publisher** will validate the incoming JSON request and publish the order event to the corresponding SNS topic. Publisher is a Lambda function which can post to SNS but is not able to access the queues and delivery tables.
2. The **Fulfillment worker** is responsible for reading eligible events from its own SQS queue and marking the successful deliveries in its own DynamoDB table. Fulfillment worker is a separate Lambda function which is based on the worker image.
3. The **Analytics worker** will be executing the same worker image as a separate Lambda function with its own queue, table and execution role. Analytics' routing rules are different from Fulfillment's, and the Analytics worker must keep working even if Fulfillment fails.
4. The **Replay service** will move the failed messages from the dead-letter queue of the selected consumer back to the main queue of that consumer and mark them as replayed. Replay is a separate Lambda function which is invoked by the operator.

The contract specifies the images, environment variables, routing rules, permissions, lifecycle behavior and request format. Do not modify the application or create new images.

## Workspace

The workspace contains Terraform, OpenTofu, the AWS provider, the AWS CLI, Python and common diagnostic tools. It does not expose the Docker CLI or Docker socket. Perform all cloud operations through the provided AWS endpoint.

There are two contract files under `/workspace/contracts/`:

- `runtime.md` defines the supplied images, AWS resources, routing rules, permissions, application behaviour and deployment lifecycle requirements.
- `manifest.schema.json` defines the required deployment manifest.

The read-only file `/workspace/config/terraform.tfvars.json` contains the deployment credentials; read it when `deploy.sh` or `destroy.sh` runs. Your writable submission directory is `/workspace/submission/`, and optional diagnostic output belongs in `/workspace/evidence/`. The image references, account ID, region and AWS endpoint are in the runtime contract. Implement every requirement in both contract files, and do not modify the contracts or the supplied images.

## Submission

Use this layout:

```text
/workspace/submission/
|-- deploy.sh
|-- destroy.sh
`-- infra/
    `-- one or more *.tf files
```

Helper scripts can be placed anywhere under `/workspace/submission/`. The directory is collected as your submission, so keep Terraform's plugin cache and other large generated files outside it (the environment already sets `TF_PLUGIN_CACHE_DIR`) and its contents under 256 MiB. `deploy.sh` and `destroy.sh` are both executed from that directory, can find `infra/` relative to themselves, and have a budget of 900 seconds per run.

- **`deploy.sh`**: Creates or updates the deployment with name set in `PULSEROUTE_PREFIX` and exits once the deployment is ready. This script needs to work when deploying an entirely new deployment, persist resource identities and caller credentials between multiple runs, fix the drift mentioned in the runtime contract and take over an existing deployment when local state is missing or unreadable.
- **`destroy.sh`**: Destroys all the resources belonging to the deployment with name set in `PULSEROUTE_PREFIX`, whether local state is present, missing or unreadable, and leaves all other resources and their data intact. Executing this script multiple times should succeed, and a later `deploy.sh` for the same prefix creates a new deployment.
- **`manifest.json`**: This file is produced by `deploy.sh` for the deployment that was deployed by it and needs to conform to `/workspace/contracts/manifest.schema.json`. Consider this file, and every other local file that holds caller secrets, a local secret.
- **`infra/`**: Contains the Terraform/OpenTofu configuration. All scored resources should be declared here and readable local `terraform.tfstate` files should be kept within the submission directory. Resources created only through the AWS CLI are not allowed.

Several deployments with different prefixes can exist at the same time and are managed from the same submission directory, including deployments whose prefix begins with another deployment's prefix.
