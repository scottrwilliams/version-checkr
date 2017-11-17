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

function makeEvent(action, eventType) {
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
      }
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
  function createContent(version) {
    return {
      data: {
        content: new Buffer(`{"version": "${version}"}`).toString('base64')
      }
    };
  }
  getContentStub.withArgs(sinon.match.has("ref", "baseSha")).resolves(createContent(oldVersion));
  getContentStub.withArgs(sinon.match.has("ref", "headSha")).resolves(createContent(newVersion));
}

beforeEach(function () {
  this.callback = sinon.spy();

  class S3 {
    constructor() {
      this.getObject = () => ({
        promise: () => Promise.resolve({
          Body: 'cert'
        })
      });
    }
  }

  process.env.WEBHOOK_SECRET = 'password';

  const GitHubApiStub = sinon.stub(GitHubApi.prototype, "authenticate");
  const getContent = sinon.stub();
  setVersion(getContent, "1.0.0", "1.0.0");

  Object.assign(this, {
    getContent,
    GitHubApiStub
  });

  GitHubApiStub.prototype.apps = {
    createInstallationToken: () => Promise.resolve({
      data: {
        token: "1"
      }
    })
  };
  GitHubApiStub.prototype.repos = {
    getContent: getContent,
    createStatus: (status) => Promise.resolve({
      data: {
        description: status.description
      }
    })
  };

  this.myLambda = proxyquire('../versioncheckr', {
    'aws-sdk': {
      S3
    },
    'github': GitHubApiStub,
    'jsonwebtoken': {
      sign: () => {}
    }
  });
});

afterEach(function () {
  this.GitHubApiStub.restore();
});

describe('versioncheckr', () => {

  it(`Missing X-GitHub-Event`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-GitHub-Event'];

    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      const err = this.callback.getCall(0).args[0];
      const result = this.callback.getCall(0).args[1];
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Missing X-GitHub-Event');
      expect(this.GitHubApiStub.notCalled).to.be.true;
    });
  });

  it(`Missing X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-Hub-Signature'];

    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      const err = this.callback.getCall(0).args[0];
      const result = this.callback.getCall(0).args[1];
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Missing X-Hub-Signature');
      expect(this.GitHubApiStub.notCalled).to.be.true;
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
      const err = this.callback.getCall(0).args[0];
      const result = this.callback.getCall(0).args[1];
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Invalid X-Hub-Signature');
      expect(this.GitHubApiStub.notCalled).to.be.true;
    });
  });

  it(`Invalid secret for X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      const err = this.callback.getCall(0).args[0];
      const result = this.callback.getCall(0).args[1];
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Invalid X-Hub-Signature');
      expect(this.GitHubApiStub.notCalled).to.be.true;
    });
  });

  it(`Valid X-Hub-Signature`, function () {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash(process.env.WEBHOOK_SECRET, body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    return this.myLambda.handler(gitHubEvent, {}, this.callback).then(() => {
      const err = this.callback.getCall(0).args[0];
      const result = this.callback.getCall(0).args[1];
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.not.equal(400);
      expect(result.body).to.not.equal('Invalid X-Hub-Signature');
      expect(this.GitHubApiStub.notCalled).to.be.true;
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
        const err = this.callback.getCall(0).args[0];
        const result = this.callback.getCall(0).args[1];
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(202);
        expect(result.body).to.equal('No action to take');
        expect(this.GitHubApiStub.notCalled).to.be.true;
      });
    });
  });

  [
    'opened',
    'reopened',
    'synchronize'
  ].forEach((gitHubAction) => {
    it(`Process pull request with action: type=${gitHubAction}`, function () {
      return this.myLambda.handler(makeEvent(gitHubAction, 'pull_request'), {}, this.callback).then(() => {
        const err = this.callback.getCall(0).args[0];
        const result = this.callback.getCall(0).args[1];
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(200);
        expect(this.GitHubApiStub.called).to.be.true;
      });
    });
  });

  [
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.1',
      isVersionHigher: true
    },
    {
      oldVersion: '0.0.0',
      newVersion: '1.0.0',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.1.0',
      isVersionHigher: true
    },
    {
      oldVersion: '9.9.99',
      newVersion: '10.0.0',
      isVersionHigher: true
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.0',
      isVersionHigher: false
    },
    {
      oldVersion: '1.0.0',
      newVersion: '0.0.0',
      isVersionHigher: false
    },
    {
      oldVersion: '1.0.1',
      newVersion: '1.0.0',
      isVersionHigher: false
    },
    {
      oldVersion: '1.1.0',
      newVersion: '1.0.9',
      isVersionHigher: false
    }
  ].forEach((data) => {
    const msg = data.isVersionHigher ?
      `Version ${data.newVersion} will replace ${data.oldVersion}` : `Version ${data.newVersion} should be bumped greater than ${data.oldVersion}`;
    it(msg, function () {
      const event = makeEvent('opened', 'pull_request');
      setVersion(this.getContent, data.oldVersion, data.newVersion);
      return this.myLambda.handler(event, {}, this.callback).then(() => {
        const err = this.callback.getCall(0).args[0];
        const result = this.callback.getCall(0).args[1];
        expect(this.callback.calledOnce).to.be.true;
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(200);
        expect(result.body).to.equal(msg);
        expect(this.GitHubApiStub.called).to.be.true;
      });
    });
  });

});
