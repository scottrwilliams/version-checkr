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

const privateKey = (() =>
  new AWS.S3().getObject({
    Bucket: process.env.PEM_BUCKET_NAME,
    Key: process.env.PEM_KEY
  }).promise()
  .then(file => file.Body.toString('utf8'))
)();

function gitHubAuthenticate(appId, cert, installationId) {
  const github = new GitHubApi();
  const payload = {
    iat: Math.floor(new Date() / 1000),
    exp: Math.floor(new Date() / 1000) + 30,
    iss: appId
  };
  github.authenticate({
    type: 'integration',
    token: jwt.sign(payload, cert, {
      algorithm: 'RS256'
    })
  });

  return github.apps.createInstallationToken({
      installation_id: installationId
    })
    .then(res => {
      github.authenticate({
        type: 'token',
        token: res.data.token
      });
      return github;
    })
    .catch(err => {
      throw new Error(JSON.stringify(err));
    });
}

function getFilesFromGitHub(github, owner, repo, headRef, baseRef) {
  const getContentParams = {
    owner: owner,
    repo: repo,
    ref: baseRef,
    path: 'package.json'
  };

  const basePackageJson = github.repos.getContent(getContentParams);
  getContentParams.ref = headRef;
  const headPackageJson = github.repos.getContent(getContentParams);

  return Promise.all([basePackageJson, headPackageJson])
    .then(([baseFile, headFile]) => ({
      github: github,
      oldVersion: JSON.parse(new Buffer(baseFile.data.content, 'base64')).version,
      newVersion: JSON.parse(new Buffer(headFile.data.content, 'base64')).version
    }))
    .catch(err => {
      throw new Error(JSON.stringify(err));
    });
}

function postStatus(github, owner, repo, sha, oldVersion, newVersion) {
  const isNewer = semver.gt(newVersion, oldVersion);
  const description = isNewer ?
    `Version ${newVersion} will replace ${oldVersion}` : `Version ${newVersion} should be bumped greater than ${oldVersion}`;

  return github.repos.createStatus({
      owner: owner,
      repo: repo,
      sha: sha,
      state: isNewer ? 'success' : 'failure',
      description: description,
      context: 'Version Checkr'
    })
    .catch(err => {
      throw new Error(JSON.stringify(err));
    });
}

function createResponse(statusCode, msg) {
  return {
    statusCode: statusCode,
    headers: {
      'Content-Type': 'text/plain'
    },
    body: msg
  };
}

module.exports.handler = (event, context, callback) => {

  const githubEvent = event.headers['X-GitHub-Event'];
  if (!githubEvent) {
    return Promise.resolve(callback(null, createResponse(400, 'Missing X-GitHub-Event')));
  }

  const sig = event.headers['X-Hub-Signature'];
  if (!sig) {
    return Promise.resolve(callback(null, createResponse(400, 'Missing X-Hub-Signature')));
  }
  if (!validateSignature(event.body, sig)) {
    return Promise.resolve(callback(null, createResponse(400, 'Invalid X-Hub-Signature')));
  }

  const pullRequest = JSON.parse(event.body);

  if (githubEvent !== 'pull_request' ||
    !(pullRequest.action === 'opened' || pullRequest.action === 'reopened' || pullRequest.action === 'synchronize')) {
    return Promise.resolve(callback(null, createResponse(202, 'No action to take')));
  }

  const installationId = pullRequest.installation.id;
  const owner = pullRequest.repository.owner.login;
  const repo = pullRequest.repository.name;
  const headRef = pullRequest.pull_request.head.ref;
  const sha = pullRequest.pull_request.head.sha;
  const baseRef = pullRequest.pull_request.base.ref;

  return Promise.resolve(privateKey)
    .then(privateKey => gitHubAuthenticate(process.env.APP_ID, privateKey, installationId))
    .then(github => getFilesFromGitHub(github, owner, repo, headRef, baseRef))
    .then(res => postStatus(res.github, owner, repo, sha, res.oldVersion, res.newVersion))
    .then(res => callback(null, createResponse(200, res.data.description)))
    .catch(err => callback(err));
};
