const queryActions = require('./queryActions');
const Application = require('./models/application');

describe('#publish', () => {
  describe('with an object that has already been published', () => {
    test('it returns 409 with a status message', done => {
      let publishedOrg = new Application({ tags: ['public'] });
      queryActions.publish(publishedOrg).catch(error => {
        expect(error.code).toEqual(409);
        expect(error.message).toEqual('Object already published');
        done();
      });
    });
  });

  describe('with an object that has not been published', () => {
    test('it adds the public tag and saves it', () => {
      let newOrg = new Application({ tags: [] });
      queryActions.publish(newOrg);
      expect(newOrg.tags[0]).toEqual(expect.arrayContaining(['public']));
    });
  });
});

test('Testing publish', () => {
  let o = {};
  o.tags = [['sysadmin']];

  expect(queryActions.isPublished(o)).toEqual(undefined);

  o.tags = [['sysadmin'], ['public']];
  expect(queryActions.isPublished(o)).toEqual(['public']);
});

describe('#isPublished', () => {
  let application = new Application({});

  test('it returns the array of public tags', () => {
    application.tags = [['sysadmin'], ['public']];
    expect(queryActions.isPublished(application)).toEqual(expect.arrayContaining(['public']));
  });

  test('it returns undefined if there is no matching public tag', () => {
    application.tags = [['sysadmin']];
    expect(queryActions.isPublished(application)).toBeUndefined();
  });
});

describe('#unpublish', () => {
  describe('with an object that has been published', () => {
    test('it removes the public tag and saves it', () => {
      let publishedOrg = new Application({ tags: ['public'] });
      queryActions.unPublish(publishedOrg);
      expect(publishedOrg.tags).toHaveLength(0);
    });
  });

  describe('with an object that is unpublished', () => {
    test('it returns 409 with a status message', done => {
      let newOrg = new Application({ tags: [] });
      queryActions.unPublish(newOrg).catch(error => {
        expect(error.code).toEqual(409);
        expect(error.message).toEqual('Object already unpublished');
        done();
      });
    });
  });
});

describe('#delete', () => {
  test('it removes the public tag', () => {
    let publishedOrg = new Application({ tags: ['public'] });
    queryActions.delete(publishedOrg);
    expect(publishedOrg.tags).toHaveLength(0);
  });

  test('it soft-deletes the object', () => {
    let newOrg = new Application({ tags: [] });
    queryActions.delete(newOrg);
    expect(newOrg.isDeleted).toEqual(true);
  });
});
