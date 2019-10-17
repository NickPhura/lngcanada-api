/**
 * Database Migration Script
 *
 * Updates the geometry property from
 *
 * {
 *   geometry: {
 *     type: 'Polygon',
 *      coordinates: []
 *   }
 * }
 *
 * to
 *
 * {
 *   geometry: {
 *     type: 'GeometryCollection',
 *     geometries: [
 *       type: 'Polygon'
 *       coordinates: []
 *     ]
 *   }
 * }
 *
 * Why?
 * The geoJson spec uses the first example for all of its standard shapes: Polygon, MultiPolygon, Line, Point, etc.
 * But it also supports GeometryCollection, which is a collection of standard shapes.  This has a different format,
 * however, and so we either need to support a whole new set of models and apis, etc, to handle 2 kinds of geometry
 * formats OR support just the GeometryCollection format, which encompasses all standard formats and covert all shapes
 * data to it.  As GeometryCollection is a valid geoJson type, every other piece of geo-spatial code works with it
 * without changes. Additionally, because ACRFD is a read-only site (we never save changes back to Tantalis), there is
 * no harm in storing the spatial data they send us in a different format.
 *
 * Note:
 *  - Only run on/after v1.1.1 - when GeometryCollection support was added.
 *  - Safe to run multiple times.
 *  - Requires MongoDB 3.4+
 */

let newGeometry = db.features.aggregate([
  {
    $match: {
      // match records that have the old format
      'geometry.coordinates': { $exists: 1 }
    }
  },
  {
    $project: {
      // update the geometry.type to always be GeometryCollection
      'geometry.type': 'GeometryCollection',
      // save the old geometry data in a temp variable
      oldGeometry: '$geometry'
    }
  },
  {
    $addFields: {
      // add the new geometries array, and add the saved old geometry data to it
      'geometry.geometries': ['$oldGeometry']
    }
  },
  {
    $project: {
      // (optional) dont project the temp oldGeometry variable as it is no longer needed
      oldGeometry: 0
    }
  }
]);

// for each aggregate result, update the real record
newGeometry.forEach(element => {
  db.features.update({ _id: element._id }, { $set: { geometry: element.geometry } });
});
