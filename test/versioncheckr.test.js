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

describe('versioncheckr', () => {

  it(`Missing X-GitHub-Event`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-GitHub-Event'];

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      try {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(400);
        expect(result.body).to.equal('Missing X-GitHub-Event');
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it(`Missing X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    delete gitHubEvent.headers['X-Hub-Signature'];

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      try {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(400);
        expect(result.body).to.equal('Missing X-Hub-Signature');
        done();
      } catch (error) {
        done(error);
      }
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
      try {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(400);
        expect(result.body).to.equal('Invalid X-Hub-Signature');
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it(`Invalid secret for X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash('not_the_secret', body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      try {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.equal(400);
        expect(result.body).to.equal('Invalid X-Hub-Signature');
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it(`Valid X-Hub-Signature`, (done) => {
    const gitHubEvent = makeEvent('action', 'event');
    const body = '{ "foo": "bar" }';
    const hash = createHash(process.env.WEBHOOK_SECRET, body);
    gitHubEvent.body = body;
    gitHubEvent.headers['X-Hub-Signature'] = `sha1=${hash}`;

    myLambda.handler(gitHubEvent, {}, (err, result) => {
      try {
        expect(err).to.not.exist;
        expect(result).to.exist;
        expect(result.statusCode).to.not.equal(400);
        expect(result.body).to.not.equal('Invalid X-Hub-Signature');
        done();
      } catch (error) {
        done(error);
      }
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
        try {
          expect(err).to.not.exist;
          expect(result).to.exist;
          expect(result.statusCode).to.equal(202);
          expect(result.body).to.equal('No action to take');
          done();
        } catch (error) {
          done(error);
        }
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
        try {
          expect(err).to.not.exist;
          expect(result).to.exist;
          expect(result.statusCode).to.equal(200);
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  [
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.1'
    },
    {
      oldVersion: '0.0.0',
      newVersion: '1.0.0'
    },
    {
      oldVersion: '1.0.0',
      newVersion: '1.1.0'
    },
    {
      oldVersion: '9.9.99',
      newVersion: '10.0.0'
    }
  ].forEach((data) => {
    it(`Version has been bumped: ${data.oldVersion} to ${data.newVersion}`, (done) => {
      const event = makeEvent('opened', 'pull_request', data.oldVersion, data.newVersion);
      myLambda.handler(event, {}, (err, result) => {
        try {
          expect(err).to.not.exist;
          expect(result).to.exist;
          expect(result.statusCode).to.equal(200);
          expect(result.body).to.equal(`Version ${data.newVersion} will replace ${data.oldVersion}`);
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

  [
    {
      oldVersion: '1.0.0',
      newVersion: '1.0.0'
    },
    {
      oldVersion: '1.0.0',
      newVersion: '0.0.0'
    },
    {
      oldVersion: '1.0.1',
      newVersion: '1.0.0'
    },
    {
      oldVersion: '1.1.0',
      newVersion: '1.0.9'
    }
  ].forEach((data) => {
    it(`Version not bumped: ${data.oldVersion} to ${data.newVersion}`, (done) => {
      const event = makeEvent('opened', 'pull_request', data.oldVersion, data.newVersion);
      myLambda.handler(event, {}, (err, result) => {
        try {
          expect(err).to.not.exist;
          expect(result).to.exist;
          expect(result.statusCode).to.equal(200);
          expect(result.body).to.equal(`Version ${data.newVersion} should be bumped greater than ${data.oldVersion}`);
          done();
        } catch (error) {
          done(error);
        }
      });
    });
  });

});
