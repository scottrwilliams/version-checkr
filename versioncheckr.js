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

async function compareVersionsFromGitHub(github, owner, repo, baseRef, headSha, pullRequestNumber, body) {
  if (!baseRef) {
    return {};
  }

  const getBaseContentParams = {
    owner,
    repo,
    ref: baseRef,
    path: 'package.json'
  };
  const getHeadContentParams = Object.assign({}, getBaseContentParams, {
    ref: headSha
  });
  const baseFile = await github.repos.getContent(getBaseContentParams);
  const headFile = await github.repos.getContent(getHeadContentParams);

  //check for comparison type from PR body
  if (body === undefined) {
    //need to fetch from PR since body doesn't come with check webhooks
    const pullRequest = await github.pullRequests.get({
      owner,
      repo,
      number: pullRequestNumber
    });
    body = pullRequest.data.body;
  }
  let releaseType = 'patch';
  if (body) {
    const match = /^#version[- ]?checke?r:\s?(major|minor|patch)/im.exec(body);
    if (match !== null) {
      releaseType = match[1].toLowerCase();
    }
  }

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
    description,
    lineNumber
  };
}

function updateCheck(github, owner, repo, baseRef, headSha, success, description, lineNumber) {

  let conclusion, title, summary;
  if (!baseRef) {
    conclusion = 'neutral';
    title = 'No PR to check';
    summary = 'Commit is not part of a pull request, so version was not checked';
  } else {
    conclusion = success ? 'success' : 'failure';
    title = success ? 'Success' : 'Failure';
    summary = description;
  }

  let checkParams = {
    owner,
    repo,
    name: 'Version Checkr',
    head_sha: headSha,
    status: 'completed',
    conclusion,
    completed_at: new Date().toISOString(),
    output: {
      title,
      summary
    }
  };
  if (baseRef && !success) {
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
    statusCode,
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
  let headSha, baseRef, pullRequestNumber, body;
  if (githubEvent === 'check_suite' &&
    (webHook.action === 'requested' || webHook.action === 'rerequested')) {
    headSha = webHook.check_suite.head_sha;
    if (webHook.check_suite.pull_requests.length > 0) {
      baseRef = webHook.check_suite.pull_requests[0].base.ref;
      pullRequestNumber = webHook.check_suite.pull_requests[0].number;
    }
  } else if (githubEvent === 'check_run' && webHook.action === 'rerequested') {
    headSha = webHook.check_run.head_sha;
    if (webHook.check_run.check_suite.pull_requests.length > 0) {
      baseRef = webHook.check_run.check_suite.pull_requests[0].base.ref;
      pullRequestNumber = webHook.check_run.check_suite.pull_requests[0].number;
    }
  } else if (githubEvent === 'pull_request' &&
    (webHook.action === 'opened' || webHook.action === 'reopened')) {
    headSha = webHook.pull_request.head.sha;
    baseRef = webHook.pull_request.base.ref;
    pullRequestNumber = webHook.pull_request.number;
    body = webHook.pull_request.body;
  } else {
    return callback(null, createResponse(202, 'No action to take'));
  }

  const installationId = webHook.installation.id;
  const owner = webHook.repository.owner.login;
  const repo = webHook.repository.name;

  try {
    const github = await gitHubAuthenticate(process.env.APP_ID, await privateKey, installationId);
    const versionCheck = await compareVersionsFromGitHub(github, owner, repo, baseRef, headSha, pullRequestNumber, body);
    const res = await updateCheck(github, owner, repo, baseRef, headSha, versionCheck.success, versionCheck.description, versionCheck.lineNumber);
    return callback(null, createResponse(baseRef ? 200 : 202, res.data.output.summary));
  } catch (e) {
    return callback(e);
  }
}
