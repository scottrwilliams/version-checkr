'use strict';

const crypto = require('crypto'),
  proxyquire = require('proxyquire'),
  expect = require('chai').expect,
  sinon = require('sinon');

function createHash(secret, body) {
  const hmac = crypto.createHmac('sha1', secret);
  hmac.setEncoding('hex');
  hmac.write(body);
  hmac.end();
  return hmac.read();
}

function makeEvent(action, eventType, commentBody = "", pullRequestIncluded = true) {

  const body = {
    action: action,
    installation: {
      id: 1
    },
    repository: {
      name: "myrepo",
      owner: {
        login: "bob"
      }
    }
  };
  const pull_request = {
    head: {
      sha: "headSha"
    },
    base: {
      ref: "baseRef"
    },
    number: 123 //TODO: test this case
  };

  if (eventType === 'pull_request') {
    body.pull_request = pull_request;
    body.pull_request.body = commentBody;
  } else {
    const check_suite = {
      pull_requests: [pull_request]
    };
    if (eventType === 'check_suite') {
      body.check_suite = check_suite;
      if (action === 'requested' && !pullRequestIncluded) {
        body.check_suite.pull_requests = [];
      }
    } else if (eventType === 'check_run') {
      body.check_run = {
        check_suite: check_suite
      };
    }
  }

  const bodyString = JSON.stringify(body);
  const hash = createHash(process.env.WEBHOOK_SECRET, bodyString);
  return {
    body: bodyString,
    headers: {
      "X-GitHub-Event": eventType,
      "X-Hub-Signature": `sha1=${hash}`,
    }
  };
}

function setVersion(getContentStub, oldVersion, newVersion) {
  const createContent = (version) => ({
    data: {
      content: new Buffer(`{"version": "${version}"}`).toString('base64')
    }
  });
  getContentStub.withArgs(sinon.match.has("ref", "baseRef")).resolves(createContent(oldVersion));
  getContentStub.withArgs(sinon.match.has("ref", "headSha")).resolves(createContent(newVersion));
}

function validateCallback(callback, statusCode, body) {
  sinon.assert.calledOnce(callback);
  const err = callback.getCall(0).args[0];
  const result = callback.getCall(0).args[1];
  if (statusCode) {
    expect(err).to.not.exist;
    expect(result).to.exist;
    expect(result.statusCode).to.equal(statusCode);
    if (body) {
      expect(result.body).to.equal(body);
    }
  } else {
    expect(err).to.exist;
    expect(result).to.not.exist;
  }
}

beforeEach(function () {
  process.env.WEBHOOK_SECRET = 'password';
  this.callback = sinon.spy();

  const authenticate = sinon.stub();
  this.authenticate = authenticate;
  const getContent = sinon.stub();
  this.getContent = getContent;
  setVersion(this.getContent, "1.0.0", "1.0.0");
  const createCheck = sinon.stub().callsFake(status => ({
    data: {
      output: {
        summary: status.output.summary
      }
    }
  }));
  this.createCheck = createCheck;
  const getPullRequest = sinon.stub().callsFake(() => ({
    data: {
      body: 'My comment'
    }
  }));
  this.getPullRequest = getPullRequest;
  class OctokitRestStub {
    constructor() {
      this.apps = {
        createInstallationToken: () => ({
          data: {
            token: "1"
          }
        })
      };
      this.checks = {
        create: createCheck
      }
      this.repos = {
        getContent: getContent
      };
      this.pullRequests = {
        get: getPullRequest
      };
      this.authenticate = authenticate;
    }
  }

  class S3 {
    getObject() {
      return {
        promise: () => ({
          Body: 'cert'
        })
      };
    }
  }

  this.myLambda = proxyquire('../versioncheckr', {
    'aws-sdk': {
      S3
    },
    '@octokit/rest': OctokitRestStub,
    'jsonwebtoken': {
      sign: () => {}
    }
  });
});

describe('versioncheckr', () => {

  it(`Missing X-GitHub-Event`, async function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-GitHub-Event'];
    await this.myLambda.handler(gitHubEvent, {}, this.callback);
    validateCallback(this.callback, 400, 'Missing X-GitHub-Event');
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`Missing X-Hub-Signature`, async function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-Hub-Signature'];
    await this.myLambda.handler(gitHubEvent, {}, this.callback);
    validateCallback(this.callback, 400, 'Missing X-Hub-Signature');
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`Invalid X-Hub-Signature`, async function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const differentBody = '{ "bar": "foo" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = differentBody;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    await this.myLambda.handler(gitHubEvent, {}, this.callback);
    validateCallback(this.callback, 400, 'Invalid X-Hub-Signature');
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`Invalid secret for X-Hub-Signature`, async function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    await this.myLambda.handler(gitHubEvent, {}, this.callback);
    validateCallback(this.callback, 400, 'Invalid X-Hub-Signature');
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`Valid X-Hub-Signature`, async function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash(process.env.WEBHOOK_SECRET, body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    await this.myLambda.handler(gitHubEvent, {}, this.callback);
    validateCallback(this.callback, 202);
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`Authenticate throws error`, async function () {
    this.authenticate.withArgs(sinon.match.has("type", "app")).throws("AuthenticateError");
    await this.myLambda.handler(makeEvent('rerequested', 'check_suite'), {}, this.callback);
    validateCallback(this.callback);
    sinon.assert.called(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`GetContent throws error`, async function () {
    this.getContent.reset();
    this.getContent.rejects("GetContentError");
    await this.myLambda.handler(makeEvent('rerequested', 'check_suite'), {}, this.callback);
    validateCallback(this.callback);
    sinon.assert.calledTwice(this.authenticate);
    sinon.assert.called(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  it(`CreateCheck throws error`, async function () {
    this.createCheck.rejects("CreateCheckError");
    await this.myLambda.handler(makeEvent('rerequested', 'check_suite'), {}, this.callback);
    validateCallback(this.callback);
    sinon.assert.calledTwice(this.authenticate);
    sinon.assert.calledTwice(this.getContent);
    sinon.assert.calledOnce(this.createCheck);
    sinon.assert.calledOnce(this.getPullRequest);
  });

  it(`PullRequest.Get throws error`, async function () {
    this.getPullRequest.rejects("PullRequestGetError");
    await this.myLambda.handler(makeEvent('rerequested', 'check_suite'), {}, this.callback);
    validateCallback(this.callback);
    sinon.assert.calledTwice(this.authenticate);
    sinon.assert.calledTwice(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.calledOnce(this.getPullRequest);
  });

  [{
      event: 'check_suite',
      action: 'completed'
    },
    {
      event: 'check_run',
      action: 'added'
    },
    {
      event: 'check_run',
      action: 'requested'
    },
    {
      event: 'release',
      action: 'published'
    },
    {
      event: 'organization',
      action: 'member_added'
    },
    {
      event: 'pull_request',
      action: 'reopened'
    }
  ].forEach((data) => {
    it(`Ignore event=${data.event} with action=${data.action}`, async function () {
      await this.myLambda.handler(makeEvent(data.action, data.event), {}, this.callback);
      validateCallback(this.callback, 202, 'No action to take');
      sinon.assert.notCalled(this.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createCheck);
      sinon.assert.notCalled(this.getPullRequest);
    });
  });

  it(`Ignore event=check_suite and action=requested when no PR info`, async function () {
    await this.myLambda.handler(makeEvent('requested', 'check_suite', '', false), {}, this.callback);
    validateCallback(this.callback, 202, 'Request did not conatin PR info');
    sinon.assert.notCalled(this.authenticate);
    sinon.assert.notCalled(this.getContent);
    sinon.assert.notCalled(this.createCheck);
    sinon.assert.notCalled(this.getPullRequest);
  });

  [{
      event: 'pull_request',
      action: 'opened'
    },
    {
      event: 'check_suite',
      action: 'requested'
    },
    {
      event: 'check_suite',
      action: 'rerequested'
    },
    {
      event: 'check_run',
      action: 'rerequested'
    }
  ].forEach((data) => {
    it(`Process pull request with event=${data.event} and action=${data.action}`, async function () {
      await this.myLambda.handler(makeEvent(data.action, data.event), {}, this.callback);
      validateCallback(this.callback, 200);
      sinon.assert.calledTwice(this.authenticate);
      sinon.assert.calledTwice(this.getContent);
      sinon.assert.calledOnce(this.createCheck);
      if (data.event === 'pull_request') {
        sinon.assert.notCalled(this.getPullRequest);
      } else {
        sinon.assert.calledOnce(this.getPullRequest);
      }
    });
  });

  it(`Checking the patch version number by default with comment`, async function () {
    setVersion(this.getContent, "1.0.0", "1.0.1");
    await this.myLambda.handler(makeEvent('rerequested', 'check_suite', 'My comment.'), {}, this.callback);
    validateCallback(this.callback, 200, 'Version 1.0.1 will replace 1.0.0');
    sinon.assert.calledTwice(this.authenticate);
    sinon.assert.calledTwice(this.getContent);
    sinon.assert.calledOnce(this.createCheck);
    sinon.assert.calledWith(this.createCheck, sinon.match.has('conclusion', 'success'));
    sinon.assert.calledOnce(this.getPullRequest);
  });

  [{
      oldVersion: '1.0.0',
      newVersion: '1.0.1',
      releaseType: 'patch',
      isVersionHigher: true
    },
    {
      oldVersion: '0.0.0',
      newVersion: '1.0.0',
      releaseType: 'patch',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.1.0',
      releaseType: 'patch',
      isVersionHigher: true
    },
    {
      oldVersion: '9.9.99',
      newVersion: '10.0.0',
      releaseType: 'patch',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.1.0',
      releaseType: 'minor',
      isVersionHigher: true
    },
    {
      oldVersion: '1.1.0',
      newVersion: '1.2.0',
      releaseType: 'minor',
      isVersionHigher: true
    },
    {
      oldVersion: '9.9.99',
      newVersion: '10.0.0',
      releaseType: 'minor',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '2.0.0',
      releaseType: 'major',
      isVersionHigher: true
    },
    {
      oldVersion: '0.99.99',
      newVersion: '1.0.0',
      releaseType: 'major',
      isVersionHigher: true
    },
    {
      oldVersion: '10.2.2',
      newVersion: '12.1.1',
      releaseType: 'major',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.0',
      releaseType: 'patch',
      isVersionHigher: false
    },
    {
      oldVersion: '1.0.0',
      newVersion: '0.0.0',
      releaseType: 'patch',
      isVersionHigher: false
    },
    {
      oldVersion: '1.0.1',
      newVersion: '1.0.0',
      releaseType: 'patch',
      isVersionHigher: false
    },
    {
      oldVersion: '1.1.0',
      newVersion: '1.0.9',
      releaseType: 'patch',
      isVersionHigher: false
    },
    {
      oldVersion: '0.0.0',
      newVersion: '0.0.1',
      releaseType: 'minor',
      isVersionHigher: false
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.99',
      releaseType: 'minor',
      isVersionHigher: false
    },
    {
      oldVersion: '1.1.1',
      newVersion: '1.1.1',
      releaseType: 'minor',
      isVersionHigher: false
    },
    {
      oldVersion: '0.0.0',
      newVersion: '0.0.1',
      releaseType: 'major',
      isVersionHigher: false
    },
    {
      oldVersion: '0.0.0',
      newVersion: '0.1.0',
      releaseType: 'major',
      isVersionHigher: false
    },
    {
      oldVersion: '1.8.8',
      newVersion: '1.9.9',
      releaseType: 'major',
      isVersionHigher: false
    }
  ].forEach((data) => {
    [{
        event: 'pull_request',
        action: 'opened'
      },
      {
        event: 'check_suite',
        action: 'requested'
      },
      {
        event: 'check_suite',
        action: 'rerequested'
      },
      {
        event: 'check_run',
        action: 'rerequested'
      }
    ].forEach((webHook) => {
      const msg = data.isVersionHigher ?
        `Version ${data.newVersion} will replace ${data.oldVersion}` : `Version ${data.newVersion} requires a ${data.releaseType} version number greater than ${data.oldVersion}`;
      const testTitle = data.isVersionHigher ? `${msg} (${data.releaseType} test)` : msg;
      it(`event=${webHook.event}, action=${webHook.action}: ${testTitle}`, async function () {
        const commentBody = `#version-checkr:${data.releaseType}`;
        const event = makeEvent(webHook.action, webHook.event, commentBody);
        this.getPullRequest.callsFake(() => ({
          data: {
            body: commentBody
          }
        }));
        setVersion(this.getContent, data.oldVersion, data.newVersion);
        await this.myLambda.handler(event, {}, this.callback);
        validateCallback(this.callback, 200, msg);
        sinon.assert.calledTwice(this.authenticate);
        sinon.assert.calledTwice(this.getContent);
        if (webHook.event === 'pull_request') {
          sinon.assert.notCalled(this.getPullRequest);
        } else {
          sinon.assert.calledOnce(this.getPullRequest);
        }
        sinon.assert.calledOnce(this.createCheck);
        sinon.assert.calledWith(this.createCheck, sinon.match.has('conclusion', data.isVersionHigher ? 'success' : 'failure'));
      });
    });
  });
});
