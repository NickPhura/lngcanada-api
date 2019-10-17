/**
 * Database Migration Script
 *
 * Deletes the commentStatus, code, review, and requestedAnonymous fields from the Comments collection
 * Why? They are currently unused.
 *
 * Note:
 *  - Safe to run multiple times.
 *  - Requires MongoDB 3.4+
 *  - Run this any time after description was removed: PRC-1029-2 for api/public AND PRC-1029 for admin
 */

db.comments.updateMany({}, { $unset: { commentStatus: 1, code: 1, review: 1, 'commentAuthor.requestedAnonymous': 1 } });
