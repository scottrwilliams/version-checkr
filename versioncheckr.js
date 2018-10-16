'use strict';

const semver = require('semver'),
  check = require('check-pull-request');

const opts = {
  appName: 'Version Checkr',
  appId: process.env.APP_ID,
  secret: process.env.WEBHOOK_SECRET,
  bucket: process.env.PEM_BUCKET_NAME,
  key: process.env.PEM_KEY,
};

const path = 'package.json';

module.exports.handler = check(opts, async pr => {
  const { baseRef } = pr;

  if (baseRef === undefined) {
    return {
      conclusion: 'neutral',
      title: 'No PR to check',
      summary: 'Commit is not part of a pull request, so version was not checked',
    };
  }

  const [baseFile, headFile, body] = await Promise.all([
    pr.getBaseContent(path),
    pr.getHeadContent(path),
    pr.getBody(),
  ]);

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
  const summary = isNewer
    ? `Version ${newVersion} will replace ${oldVersion}`
    : `Version ${newVersion} requires a ${releaseType} version number greater than ${oldVersion}`;

  return {
    summary,
    conclusion: isNewer ? 'success' : 'failure',
    title: isNewer ? 'Success' : 'Failure',
    annotations: isNewer ? [] : [{
      path,
      start_line: lineNumber,
      end_line: lineNumber,
      annotation_level: 'failure',
      message: summary
    }]
  };
});
