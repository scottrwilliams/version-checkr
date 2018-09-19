'use strict';

const GitHubApi = require('@octokit/rest'),
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

const privateKey = (async () => {
  const file = await new AWS.S3().getObject({
    Bucket: process.env.PEM_BUCKET_NAME,
    Key: process.env.PEM_KEY
  }).promise();
  return file.Body.toString('utf8');
})();

async function gitHubAuthenticate(appId, cert, installationId) {
  const github = new GitHubApi();
  const payload = {
    iat: Math.floor(new Date() / 1000),
    exp: Math.floor(new Date() / 1000) + 30,
    iss: appId
  };

  github.authenticate({
    type: 'app',
    token: jwt.sign(payload, cert, {
      algorithm: 'RS256'
    })
  });

  const installationToken = await github.apps.createInstallationToken({
    installation_id: installationId
  });

  github.authenticate({
    type: 'token',
    token: installationToken.data.token
  });
  return github;
}

async function compareVersionsFromGitHub(github, owner, repo, baseSha, headSha, releaseType) {
  const getBaseContentParams = {
    owner: owner,
    repo: repo,
    ref: baseSha,
    path: 'package.json'
  };
  const getHeadContentParams = Object.assign({}, getBaseContentParams, {
    ref: headSha
  });
  const baseFile = await github.repos.getContent(getBaseContentParams);
  const headFile = await github.repos.getContent(getHeadContentParams);

  const newVersionText = Buffer.from(headFile.data.content, 'base64').toString();
  const newVersionSubString = newVersionText.substring(0, newVersionText.indexOf('"version"'));
  const lineNumber = newVersionSubString.split('\n').length;
  const oldVersion = JSON.parse(Buffer.from(baseFile.data.content, 'base64')).version;
  const newVersion = JSON.parse(newVersionText).version
  const oldVersionIncremented = semver.inc(oldVersion, releaseType);
  const isNewer = semver.gte(newVersion, oldVersionIncremented);
  const description = isNewer ?
    `Version ${newVersion} will replace ${oldVersion}` : `Version ${newVersion} requires a ${releaseType} version number greater than ${oldVersion}`;

  return {
    success: isNewer,
    description: description,
    lineNumber: lineNumber
  };
}

function updateCheck(github, owner, repo, sha, success, description, lineNumber) {

  let checkParams = {
    owner: owner,
    repo: repo,
    name: 'Version Checkr',
    head_sha: sha,
    status: 'completed',
    conclusion: success ? 'success' : 'failure',
    completed_at: new Date().toISOString(),
    output: {
      title: success ? 'Success' : 'Failure',
      summary: description
    }
  };
  if (!success) {
    checkParams.output.annotations = [{
      path: 'package.json',
      start_line: lineNumber,
      end_line: lineNumber,
      annotation_level: 'failure',
      message: description
    }];
  }

  return github.checks.create(checkParams);
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

module.exports.handler = async (event, context, callback) => {

  const githubEvent = event.headers['X-GitHub-Event'];
  if (!githubEvent) {
    return callback(null, createResponse(400, 'Missing X-GitHub-Event'));
  }

  const sig = event.headers['X-Hub-Signature'];
  if (!sig) {
    return callback(null, createResponse(400, 'Missing X-Hub-Signature'));
  }
  if (!validateSignature(event.body, sig)) {
    return callback(null, createResponse(400, 'Invalid X-Hub-Signature'));
  }

  const webHook = JSON.parse(event.body);
  let baseSha, headSha, body;
  if (githubEvent === 'check_suite' &&
    (webHook.action === 'requested' || webHook.action === 'rerequested')) {
    //TODO: why are pull_requests empty for requested action? Contacted GitHub support
    baseSha = webHook.check_suite.pull_requests[0].base.sha;
    headSha = webHook.check_suite.pull_requests[0].head.sha;
    body = webHook.check_suite.pull_requests[0].body;
  } else if (githubEvent === 'check_run' && webHook.action === 'rerequested') {
    baseSha = webHook.check_run.check_suite.pull_requests[0].base.sha;
    headSha = webHook.check_run.check_suite.pull_requests[0].head.sha;
    body = webHook.check_run.check_suite.pull_requests[0].body;
  } else {
    return callback(null, createResponse(202, 'No action to take'));
  }

  const installationId = webHook.installation.id;
  const owner = webHook.repository.owner.login;
  const repo = webHook.repository.name;

  //TODO - how to get this info? Worth another request?
  let checking = 'patch';
  if (body) {
    const match = /^#version[- ]?checke?r:\s?(major|minor|patch)/im.exec(body);
    if (match !== null) {
      checking = match[1].toLowerCase();
    }
  }

  try {
    const github = await gitHubAuthenticate(process.env.APP_ID, await privateKey, installationId);
    const versionCheck = await compareVersionsFromGitHub(github, owner, repo, baseSha, headSha, checking);
    const res = await updateCheck(github, owner, repo, headSha, versionCheck.success, versionCheck.description, versionCheck.lineNumber);
    return callback(null, createResponse(200, res.data.output.summary));
  } catch (e) {
    return callback(e);
  }
}
