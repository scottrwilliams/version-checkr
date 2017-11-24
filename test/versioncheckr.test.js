'use strict';

const crypto = require('crypto'),
  proxyquire = require('proxyquire'),
  expect = require('chai').expect,
  sinon = require('sinon'),
  GitHubApi = require('github');

function createHash(secret, body) {
  const hmac = crypto.createHmac('sha1', secret);
  hmac.setEncoding('hex');
  hmac.write(body);
  hmac.end();
  return hmac.read();
}

function makeEvent(action, eventType, commentBody = "") {
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
    },
    pull_request: {
      head: {
        sha: "headSha"
      },
      base: {
        sha: "baseSha"
      },
      body: commentBody
    }
  };

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
  getContentStub.withArgs(sinon.match.has("ref", "baseSha")).resolves(createContent(oldVersion));
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

  GitHubApi.prototype.apps = {
    createInstallationToken: () => Promise.resolve({
      data: {
        token: "1"
      }
    })
  };

  this.getContent = sinon.stub();
  setVersion(this.getContent, "1.0.0", "1.0.0");
  this.createStatus = sinon.stub().callsFake((status) => Promise.resolve({
    data: {
      description: status.description
    }
  }));
  GitHubApi.prototype.repos = {
    getContent: this.getContent,
    createStatus: this.createStatus
  };

  const GitHubStubInstance = sinon.createStubInstance(GitHubApi);
  this.GitHubStubInstance = GitHubStubInstance;
  this.GitHubApiStub = sinon.spy(function () {
    return GitHubStubInstance;
  });

  class S3 {
    getObject() {
      return {
        promise: () => Promise.resolve({
          Body: 'cert'
        })
      };
    }
  }

  this.myLambda = proxyquire('../versioncheckr', {
    'aws-sdk': {
      S3
    },
    'github': this.GitHubApiStub,
    'jsonwebtoken': {
      sign: () => {}
    }
  });
});

describe('versioncheckr', () => {

  it(`Missing X-GitHub-Event`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-GitHub-Event'];
    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      validateCallback(this.callback, 400, 'Missing X-GitHub-Event');
      sinon.assert.notCalled(this.GitHubApiStub);
      sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`Missing X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-Hub-Signature'];
    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      validateCallback(this.callback, 400, 'Missing X-Hub-Signature');
      sinon.assert.notCalled(this.GitHubApiStub);
      sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`Invalid X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const differentBody = '{ "bar": "foo" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = differentBody;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      validateCallback(this.callback, 400, 'Invalid X-Hub-Signature');
      sinon.assert.notCalled(this.GitHubApiStub);
      sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`Invalid secret for X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      validateCallback(this.callback, 400, 'Invalid X-Hub-Signature');
      sinon.assert.notCalled(this.GitHubApiStub);
      sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`Valid X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash(process.env.WEBHOOK_SECRET, body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;
    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      validateCallback(this.callback, 202);
      sinon.assert.notCalled(this.GitHubApiStub);
      sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`Authenticate throws error`, function () {
    this.GitHubStubInstance.authenticate.withArgs(sinon.match.has("type", "token")).throws("AuthenticateError");
    return this.myLambda.handler(makeEvent('opened', 'pull_request'), {}, this.callback).then(() => {
      validateCallback(this.callback);
      sinon.assert.calledWithNew(this.GitHubApiStub);
      sinon.assert.called(this.GitHubStubInstance.authenticate);
      sinon.assert.notCalled(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`GetContent throws error`, function () {
    this.getContent.reset();
    this.getContent.rejects("GetContentError");
    return this.myLambda.handler(makeEvent('opened', 'pull_request'), {}, this.callback).then(() => {
      validateCallback(this.callback);
      sinon.assert.calledWithNew(this.GitHubApiStub);
      sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
      sinon.assert.called(this.getContent);
      sinon.assert.notCalled(this.createStatus);
    });
  });

  it(`CreateStatus throws error`, function () {
    this.createStatus.rejects("CreateStatusError");
    return this.myLambda.handler(makeEvent('opened', 'pull_request'), {}, this.callback).then(() => {
      validateCallback(this.callback);
      sinon.assert.calledWithNew(this.GitHubApiStub);
      sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
      sinon.assert.calledTwice(this.getContent);
      sinon.assert.calledOnce(this.createStatus);
    });
  });

  [
    {
      event: 'pull_request',
      action: 'create'
    },
    {
      event: 'pull_request',
      action: 'fork'
    },
    {
      event: 'release',
      action: 'published'
    },
    {
      event: 'organization',
      action: 'member_added'
    }
  ].forEach((data) => {
    it(`Ignore event=${data.event} with action=${data.action}`, function () {
      return this.myLambda.handler(makeEvent(data.action, data.event), {}, this.callback).then(() => {
        validateCallback(this.callback, 202, 'No action to take');
        sinon.assert.notCalled(this.GitHubApiStub);
        sinon.assert.notCalled(this.GitHubStubInstance.authenticate);
        sinon.assert.notCalled(this.getContent);
        sinon.assert.notCalled(this.createStatus);
      });
    });
  });

  [
    {
      commentBody: '#version-checkr:skip',
      testing: 'basic'
    },
    {
      commentBody: 'My comment.\n#version checker: skip',
      testing: 'on newline'
    },
    {
      commentBody: 'Hello.\n\n#VeRsiOnCHECKER:skIp',
      testing: 'mixed caps'
    }
  ].forEach((data) => {
    it(`Skip comment ${data.testing}`, function () {
      return this.myLambda.handler(makeEvent('opened', 'pull_request', data.commentBody), {}, this.callback).then(() => {
        validateCallback(this.callback, 200, 'Skipped the version check');
        sinon.assert.calledWithNew(this.GitHubApiStub);
        sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
        sinon.assert.notCalled(this.getContent);
        sinon.assert.calledOnce(this.createStatus);
      });
    });
  });

  [
    {
      commentBody: 'version-checkr:skip',
      testing: 'missing @'
    },
    {
      commentBody: 'My comment.',
      testing: 'missing definition'
    },
    {
      commentBody: '#version-checkr:off',
      testing: 'without skip action'
    }
  ].forEach((data) => {
    it(`Do not skip comment ${data.testing}`, function () {
      return this.myLambda.handler(makeEvent('opened', 'pull_request', data.commentBody), {}, this.callback).then(() => {
        validateCallback(this.callback, 200);
        sinon.assert.calledWithNew(this.GitHubApiStub);
        sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
        sinon.assert.calledTwice(this.getContent);
        sinon.assert.calledOnce(this.createStatus);
      });
    });
  });

  [
    'opened',
    'reopened',
    'synchronize',
    'edited'
  ].forEach((gitHubAction) => {
    it(`Process pull request with action type ${gitHubAction}`, function () {
      return this.myLambda.handler(makeEvent(gitHubAction, 'pull_request'), {}, this.callback).then(() => {
        validateCallback(this.callback, 200);
        sinon.assert.calledWithNew(this.GitHubApiStub);
        sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
        sinon.assert.calledTwice(this.getContent);
        sinon.assert.calledOnce(this.createStatus);
      });
    });
  });

  it(`Checking the patch version number by default`, function () {
    setVersion(this.getContent, "1.0.0", "1.0.1");
    return this.myLambda.handler(makeEvent('opened', 'pull_request'), {}, this.callback).then(() => {
      validateCallback(this.callback, 200, 'Version 1.0.1 will replace 1.0.0');
      sinon.assert.calledWithNew(this.GitHubApiStub);
      sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
      sinon.assert.calledTwice(this.getContent);
      sinon.assert.calledOnce(this.createStatus);
    });
  });

  [
    {
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
    const msg = data.isVersionHigher ?
      `Version ${data.newVersion} will replace ${data.oldVersion}` : `Version ${data.newVersion} requires a ${data.releaseType} version number greater than ${data.oldVersion}`;
    const testTitle = data.isVersionHigher ? `${msg} (${data.releaseType} test)` : msg;
    it(testTitle, function () {
      const commentBody = `#version-checkr:${data.releaseType}`;
      const event = makeEvent('opened', 'pull_request', commentBody);
      setVersion(this.getContent, data.oldVersion, data.newVersion);
      return this.myLambda.handler(event, {}, this.callback).then(() => {
        validateCallback(this.callback, 200, msg);
        sinon.assert.calledWithNew(this.GitHubApiStub);
        sinon.assert.calledTwice(this.GitHubStubInstance.authenticate);
        sinon.assert.calledTwice(this.getContent);
        sinon.assert.calledOnce(this.createStatus);
      });
    });
  });
});
