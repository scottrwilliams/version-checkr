'use strict';

const GitHubApi = require('github'),
      AWS = require('aws-sdk'),
      jwt = require('jsonwebtoken'),
      semver = require('semver'),
      crypto = require('crypto');

function validateSignature(body, xHubSignature) {

  const hmac = crypto.createHmac('sha1', process.env.WEBHOOK_SECRET);
  const bodySig = `sha1=${hmac.update(body).digest('hex')}`;
  const bufferBodySig = Buffer.from(bodySig, 'utf8');
  const bufferXHubSig = Buffer.from(xHubSignature, 'utf8');

  return crypto.timingSafeEqual(bufferBodySig, bufferXHubSig);
}

const privateKey = (() => {

    const s3 = new AWS.S3();
    return s3.getObject({
      Bucket: process.env.PEM_BUCKET_NAME,
      Key: process.env.PEM_KEY
    })
    .promise()
    .then( file => file.Body.toString('utf8') );
})();

function gitHubAuthenticate (appId, cert, installationId) {

  const payload = {
    iat: Math.floor(new Date() / 1000),
    exp: Math.floor(new Date() / 1000) + 30,
    iss: appId
  };
  const token = jwt.sign(payload, cert, {algorithm: 'RS256'});

  const github = new GitHubApi();
  github.authenticate({
    type: 'integration',
    token: token
  });

  return github.apps.createInstallationToken({
      installation_id: installationId
    }).then(res => {
        github.authenticate(
          {type: 'token',
           token: res.data.token
        });
        return github;
    });
}

function getFilesFromGitHub (github, owner, repo, newRef) {

  const getContentParams = {
    owner: owner,
    repo: repo,
    path: "package.json"
  };
  const currentPackageJson = github.repos.getContent(getContentParams);

  getContentParams.ref = newRef;
  const newPackageJson = github.repos.getContent(getContentParams);

  return Promise.all([currentPackageJson, newPackageJson])
    .then(([oldFile, newFile]) => ({
        github: github,
        oldVersion: JSON.parse(new Buffer(oldFile.data.content, 'base64')).version,
        newVersion: JSON.parse(new Buffer(newFile.data.content, 'base64')).version
    }));
}

function postStatus (github, owner, repo, sha, oldVersion, newVersion) {

  const isNewer = semver.gt(newVersion, oldVersion);

  return github.repos.createStatus({
    owner: owner,
    repo: repo,
    sha: sha,
    state: isNewer ? "success" : "failure",
    description: isNewer ? `Version ${newVersion} will replace ${oldVersion}` : `Version ${newVersion} should be bumped greater than ${oldVersion}`,
    context: "Version Checkr"
  });
}

module.exports.handler = (event, context, callback) => {

  console.log(event.body);

  const githubEvent = event.headers['X-GitHub-Event'];
  const pullRequest = JSON.parse(event.body);
  if (githubEvent !== 'pull_request' || !( pullRequest.action === 'opened' || pullRequest.action === 'reopened' || pullRequest.action === 'synchronize' ) ) {
    return callback( null, {
        statusCode: 202,
        body: "No action to take"
      });
  }

  if( !validateSignature(event.body, event.headers['X-Hub-Signature']) ){
    return callback( null, {
        statusCode: 400,
        body: "Invalid X-Hub-Signature"
      });
  }

  const installationId = pullRequest.installation.id;
  const owner = pullRequest.repository.owner.login;
  const repo = pullRequest.repository.name;
  const newRef = pullRequest.pull_request.head.ref;
  const sha = pullRequest.pull_request.head.sha;

  Promise.resolve( privateKey )
  .then( privateKey => gitHubAuthenticate(process.env.APP_ID, privateKey, installationId) )
  .then( github => getFilesFromGitHub(github, owner, repo, newRef) )
  .then( res => postStatus(res.github, owner, repo, sha, res.oldVersion, res.newVersion) )
  .then( () => callback(null, {statusCode: 204}) )
  .catch(err => {
    callback(err);
  });
};
