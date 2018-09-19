# version-checkr
Creates a serverless endpoint for a GitHub App to check if NPM versions get bumped during pull requests.

## Creating a GitHub App

1. Clone this repository
2. `npm install`
3. Generate a secret token (i.e. `ruby -rsecurerandom -e 'puts SecureRandom.hex(20)'`)
4. Register a [new GitHub app](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/). Use token from step 3 for the "Webhook secret"
5. Required App permissions & webhooks:
* Set `Checks` permission to `Read & write`
* Set `Single file` permission to `Read-only` and set the path to `package.json`
* Every other permission should be set to `No access`
* No webhooks need to be selected under `Subscribe to events`. GitHub will automatically send `check_suite` and `check_run` events
6. Save app and make note of the App Id
7. [Generate a private key](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/#generating-a-private-key) for the App and save it
8. Ensure serverless is [configured with appropriate AWS credentials](https://serverless.com/framework/docs/providers/aws/guide/quick-start/)
9. Run a severless deploy `npm run deploy -- --app_id [from step 5] --webhook_secret [from step 3]`. Note the endpoint URL that comes back
10. Go back into the GitHub App settings and set the "Webhook URL" to the endpoint URL from step 8
11. Take the private key from step 5 and store it as `key.pem` in an S3 bucket called `versioncheckr-cfg` (or override environment variables `PEM_BUCKET_NAME` and `PEM_KEY`)
12. [Install](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-installation-options-for-github-apps/) and enable the App for your GitHub organization and/or selected repos

## Using version-checkr

Uses [GitHub Checks API](https://developer.github.com/v3/checks/) to show if the NPM version from pull request branch is greater than the version of the base branch.

#### Skip checks

Use `skip-checks: true`, as described [here](https://help.github.com/articles/about-status-checks/#skipping-and-requesting-checks-for-individual-commits)

#### Evaluation modes

Place the text `#version-checkr: <flag>` at the start of any line in the pull request description to set any of the flags below.

1. `#version-checkr: patch` (**default mode** if no flag is scpecified). Ensures the patch version is incremented by at least 1 version. Example: `1.0.0` -> `1.0.1`
2. `#version-checkr: minor` ensures the patch version is incremented by at least 1 version. Example: `1.0.1` -> `1.1.0`
3. `#version-checkr: major` ensures the major version is incremented by at least 1 version. Example: `1.1.0` -> `2.0.0`
