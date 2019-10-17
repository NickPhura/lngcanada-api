/**
 * Database Migration Script
 *
 * Deletes the _proponent and code fields from the Applications collection.
 * Why? They are currently unused.
 *
 * Note:
 *  - Safe to run multiple times.
 *  - Requires MongoDB 3.4+
 *  - Run this any time after description was removed: PRC-1029-2 for api/public AND PRC-1029 for admin
 */

db.applications.updateMany({}, { $unset: { _proponent: 1, code: 1 } });
