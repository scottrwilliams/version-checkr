# version-checkr
Creates a serverless endpoint for a GitHub App to check if NPM versions get bumped during pull requests.

Uses [GitHub Commit Status API](https://github.com/blog/1227-commit-status-api) to show if the NPM version from pull request branch is greater than the version of the base branch.

## Setup

1. Clone this repository
2. `npm install`
3. Generate a secret token (i.e. `ruby -rsecurerandom -e 'puts SecureRandom.hex(20)'`)
4. Register a [new GitHub app](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/). Use token from step 3 for the "Webhook secret"
5. Save app and make note of the App Id
6. [Generate a private key](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/#generating-a-private-key) for the App and save it
7. Ensure serverless is [configured with appropriate AWS credentials](https://serverless.com/framework/docs/providers/aws/guide/quick-start/)
8. Run a severless deploy `npm run deploy -- --app_id [from step 5] --webhook_secret [from step 3]`. Note the endpoint URL that comes back
9. Go back into the GitHub App settings and set the "Webhook URL" to the endpoint URL from step 8
10. Take the private key from step 5 and store it as `key.pem` in an S3 bucket called `versioncheckr-cfg` (or override environment variables `PEM_BUCKET_NAME` and `PEM_KEY`) 
11. [Install](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-installation-options-for-github-apps/) and enable the App for your GitHub organization and/or selected repos
