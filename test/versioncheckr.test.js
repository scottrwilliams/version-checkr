'use strict';

const crypto = require('crypto'),
  proxyquire = require('proxyquire'),
  expect = require('chai').expect;

class S3 {
  constructor() {
    this.getObject = () => ({
      promise: () => Promise.resolve({
        Body: 'cert'
      })
    });
  }
}

class GitHubApi {
  constructor() {
    this.authenticate = () => {};
    this.apps = {
      createInstallationToken: () => Promise.resolve({
        data: {
          token: "1"
        }
      })
    };
    this.repos = {
      getContent: (params) => Promise.resolve({
        data: {
          content: new Buffer(`{"version": "${params.ref }"}`).toString('base64')
        }
      }),
      createStatus: (status) => Promise.resolve({
        data: {
          description: status.description
        }
      })
    };
  }
}

const myLambda = proxyquire('../versioncheckr', {
  'aws-sdk': {
    S3
  },
  'github': GitHubApi,
  'jsonwebtoken': {
    sign: () => {}
  }
});

function createHash(secret, body) {
  const hmac = crypto.createHmac('sha1', secret);
  hmac.setEncoding('hex');
  hmac.write(body);
  hmac.end();
  return hmac.read();
}

function makeEvent(action, eventType, oldVersion = "1.0.0", newVersion = "1.0.0") {
  const body = {
    action: action,
    installation: {
      id: 1
    },
    repository: {
      owner: "Bob",
      name: "repo"
    },
    pull_request: {
      head: {
        ref: newVersion, //cheat by passing version through ref since mocked GitHubApi uses it in getContent
        sha: "9049f1265b7d61be4a8904a9a27120d2064dab3b"
      },
      base: {
        ref: oldVersion
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

beforeEach(() => {
  process.env.WEBHOOK_SECRET = 'password';
});

//since versioncheckr uses promises that aren't returned to the caller
//https://github.com/mochajs/mocha/issues/2797
process.on('unhandledRejection', e => {
  throw e;
});

describe('versioncheckr', () => {

  it(`Missing X-GitHub-Event`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-GitHub-Event'];

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Missing X-GitHub-Event');
      done();
    });
  });

  it(`Missing X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-Hub-Signature'];

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Missing X-Hub-Signature');
      done();
    });
  });

  it(`Invalid X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const differentBody = '{ "bar": "foo" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = differentBody;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Invalid X-Hub-Signature');
      done();
    });
  });

  it(`Invalid secret for X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.equal(400);
      expect(result.body).to.equal('Invalid X-Hub-Signature');
      done();
    });
  });

  it(`Valid X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash(process.env.WEBHOOK_SECRET, body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      expect(err).to.not.exist;
      expect(result).to.exist;
      expect(result.statusCode).to.not.equal(400);
      expect(result.body).to.not.equal('Invalid X-Hub-Signature');
      done();
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
    it(`Ignore event=${data.event} with action=${data.action}`, (done) => {
      myLambda.handler(makeEvent(data.action, data.event), {}, (err, result) => {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(202);
        expect(result.body).to.equal('No action to take');
        done();
      });
    });
  });

  [
    'opened',
    'reopened',
    'synchronize'
  ].forEach((gitHubAction) => {
    it(`Process pull request with action: type=${gitHubAction}`, (done) => {
      myLambda.handler(makeEvent(gitHubAction, 'pull_request'), {}, (err, result) => {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(200);
        done();
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
    it(msg, (done) => {
      const event = makeEvent('opened', 'pull_request', data.oldVersion, data.newVersion);
      myLambda.handler(event, {}, (err, result) => {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(200);
        expect(result.body).to.equal(msg);
        done();
      });
    });
  });

});
