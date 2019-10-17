/**
 * Database Migration Script
 *
 * Deletes the code field from the CommentPeriods collection.
 * Why? They are currently unused.
 *
 * Note:
 *  - Safe to run multiple times.
 *  - Requires MongoDB 3.4+
 *  - Run this any time after description was removed: PRC-1029-2 for api/public AND PRC-1029 for admin
 */

db.commentperiods.updateMany({}, { $unset: { code: 1 } });
