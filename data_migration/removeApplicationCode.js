/**
 * Database Migration Script
 *
 * Deletes the code field from the Decisions collection.
 * Why? They are currently unused.
 *
 * Note:
 *  - Safe to run multiple times.
 *  - Requires MongoDB 3.4+
 *  - Run this any time after description was removed: PRC-1029-2 for api/public AND PRC-1029 for admin
 */

db.decisions.updateMany({}, { $unset: { code: 1, _review: 1 } });
