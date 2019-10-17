module.exports = require('../models')('Comment', {
  _addedBy: { type: String, default: null },
  _commentPeriod: { type: 'ObjectId', ref: 'CommentPeriod', default: null, index: true },
  // Note: Default on tag property is purely for display only, they have no real effect on the model
  // This must be done in the code.
  tags: [[{ type: String, trim: true, default: '[["sysadmin"]]' }]],
  name: { type: String, trim: true },

  // free form field (supports rich text?)
  comment: { type: String, default: '' },

  commentAuthor: {
    // May reference a particular user in the future.
    _userId: { type: 'ObjectId', ref: 'User' },

    // All the following details are in case there's no binding to a particular user objId
    // TODO: Should this be cleaned up a bit more?
    orgName: { type: String, default: null },
    contactName: { type: String, default: '' },
    location: { type: String, default: '' },

    internal: {
      email: { type: String, default: '' },
      phone: { type: String, default: '' },
      tags: [[{ type: String, trim: true, default: '[["sysadmin"]]' }]]
    },

    tags: [[{ type: String, trim: true, default: '[["sysadmin"]]' }]]
  },

  // TODO: More date fields?
  dateAdded: { type: Date, default: Date.now() },

  isDeleted: { type: Boolean, default: false }
});
