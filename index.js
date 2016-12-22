'use strict';
var fetch = require('node-fetch');
var url = require('url');
var Promise = require('lie');

// ASHA settings
const database = 'asha-fusion-dev';
const roles = ['staff'];
const validator = function(newDoc, oldDoc, userCtx) {
  var role = "staff";
  if (userCtx.roles.indexOf("_admin") === -1 && userCtx.roles.indexOf(role) === -1) {
    throw({forbidden : "Only users with role " + role + " or an admin can modify this database."});
  }
};
const auth_validator = function(newDoc, oldDoc, userCtx, secObj) {
      if (newDoc._deleted === true) {
          // allow deletes by admins and matching users
          // without checking the other fields
          if ((userCtx.roles.indexOf('_admin') !== -1) ||
              (userCtx.name == oldDoc.name)) {
              return;
          } else {
              throw({forbidden: 'Only admins may delete other user docs.'});
          }
      }

      if ((oldDoc && oldDoc.type !== 'user') || newDoc.type !== 'user') {
          throw({forbidden : 'doc.type must be user'});
      } // we only allow user docs for now

      if (!newDoc.name) {
          throw({forbidden: 'doc.name is required'});
      }

      if (!newDoc.roles) {
          throw({forbidden: 'doc.roles must exist'});
      }

      if (!isArray(newDoc.roles)) {
          throw({forbidden: 'doc.roles must be an array'});
      }

      for (var idx = 0; idx < newDoc.roles.length; idx++) {
          if (typeof newDoc.roles[idx] !== 'string') {
              throw({forbidden: 'doc.roles can only contain strings'});
          }
      }

      if (newDoc._id !== ('org.couchdb.user:' + newDoc.name)) {
          throw({
              forbidden: 'Doc ID must be of the form org.couchdb.user:name'
          });
      }

      if (oldDoc) { // validate all updates
          if (oldDoc.name !== newDoc.name) {
              throw({forbidden: 'Usernames can not be changed.'});
          }
      }

      if (newDoc.password_sha && !newDoc.salt) {
          throw({
              forbidden: 'Users with password_sha must have a salt.' +
                  'See /_utils/script/couch.js for example code.'
          });
      }

      if (newDoc.password_scheme === "pbkdf2") {
          if (typeof(newDoc.iterations) !== "number") {
             throw({forbidden: "iterations must be a number."});
          }
          if (typeof(newDoc.derived_key) !== "string") {
             throw({forbidden: "derived_key must be a string."});
          }
      }

      var is_server_or_database_admin = function(userCtx, secObj) {
          return true;

          // see if the user is a server admin
          if(userCtx.roles.indexOf('_admin') !== -1) {
              return true; // a server admin
          }

          // see if the user a database admin specified by name
          if(secObj && secObj.admins && secObj.admins.names) {
              if(secObj.admins.names.indexOf(userCtx.name) !== -1) {
                  return true; // database admin
              }
          }

          // see if the user a database admin specified by role
          if(secObj && secObj.admins && secObj.admins.roles) {
              var db_roles = secObj.admins.roles;
              for(var idx = 0; idx < userCtx.roles.length; idx++) {
                  var user_role = userCtx.roles[idx];
                  if(db_roles.indexOf(user_role) !== -1) {
                      return true; // role matches!
                  }
              }
          }

          return false; // default to no admin
      }

      if (!is_server_or_database_admin(userCtx, secObj)) {
          if (oldDoc) { // validate non-admin updates
              if (userCtx.name !== newDoc.name) {
                  throw({
                      forbidden: 'You may only update your own user document.'
                  });
              }
              // validate role updates
              var oldRoles = oldDoc.roles.sort();
              var newRoles = newDoc.roles.sort();

              if (oldRoles.length !== newRoles.length) {
                  throw({forbidden: 'Only _admin may edit roles'});
              }

              for (var i = 0; i < oldRoles.length; i++) {
                  if (oldRoles[i] !== newRoles[i]) {
                      throw({forbidden: 'Only _admin may edit roles'});
                  }
              }
          } else if (newDoc.roles.length > 0) {
              //throw({forbidden: 'Only _admin may set roles'});

              // no admin role
              var adminroles = secObj && secObj.admins && secObj.admins.roles || []
              for (var i = 0; i < newDoc.roles.length; i++) {
                  if (newDoc.roles[i] === '_admin' || adminroles.indexOf(newDoc.roles[i]) !== -1) {
                      throw({
                          forbidden:
                          'Creating admin role is not permitted.'
                      });
                  }
              }
          }
      }

      // no system roles in users db
      for (var i = 0; i < newDoc.roles.length; i++) {
          if (newDoc.roles[i][0] === '_') {
              throw({
                  forbidden:
                  'No system roles (starting with underscore) in users db.'
              });
          }
      }

      // no system names as names
      if (newDoc.name[0] === '_') {
          throw({forbidden: 'Username may not start with underscore.'});
      }

      var badUserNameChars = [':'];

      for (var i = 0; i < badUserNameChars.length; i++) {
          if (newDoc.name.indexOf(badUserNameChars[i]) >= 0) {
              throw({forbidden: 'Character `' + badUserNameChars[i] +
                      '` is not allowed in usernames.'});
          }
      }
  };


var requests = [
  {
    path: '/_config/httpd/enable_cors',
    value: '"true"'
  },
  {
    path: '/_config/cors/origins',
    value: '"*"'
  },
  {
    path: '/_config/cors/credentials',
    value: '"true"'
  },
  {
    path: '/_config/cors/methods',
    value: '"GET, PUT, POST, HEAD, DELETE"'
  },
  {
    path: '/_config/cors/headers',
    value: '"accept, authorization, content-type, origin, referer, x-csrf-token"'
  },
//  {
//    path: '/_config/httpd/require_valid_user',
//    value: '"true"'
//  },
//  {
//    path: '/' + database + '/_security',
//    value: JSON.stringify({
//      'members': {
//        'roles': roles
//      }
//    })
//  },
//// TODO: not POST but PUT
////  {
////    path: '/_users/_design/_auth',
////    value: JSON.stringify({
////      language: 'javascript',
////      validate_doc_update: auth_validator.toString()
////    })
////  },
//  {
//    path: '/' + database + '/_design/only_staffs',
//    value: JSON.stringify({
//      validate_doc_update: validator.toString()
//    })
//  }
];

function formatUrl(baseUrl, auth, path) {
  var urlObject = url.parse(baseUrl + path);

  if (auth) {
    urlObject.auth = auth;
  }

  return url.format(urlObject);
}

function updateConfig(urlString, value) {
  return fetch(urlString, {method: 'PUT', body: value}).then(function (resp) {
    if (resp.status === 200) {
      return;
    }
    return resp.text().then(function (text) {
      throw new Error('status ' + resp.status + ' ' + text);
    });
  });
}

function doCouch1(baseUrl, auth) {
  return Promise.all(requests.map(function (req) {
    var urlString = formatUrl(baseUrl, auth, req.path);
    return updateConfig(urlString, req.value);
  }));
}

function doCouch2(baseUrl, auth, membershipResp) {
  // do the Couch1 logic for all cluster_nodes
  // see https://github.com/klaemo/docker-couchdb/issues/42#issuecomment-169610897
  return membershipResp.json().then(function (members) {
    return Promise.all(members.cluster_nodes.map(function (node) {
      return Promise.all(requests.map(function (req) {
        var path = '/_node/' + node + '/' + req.path;
        var urlString = formatUrl(baseUrl, auth, path);
        return updateConfig(urlString, req.value);
      }));
    }));
  });
}

function addCors(baseUrl, auth) {
  // check if we're dealing with couch 1 or couch 2
  var urlString = formatUrl(baseUrl, auth, '/_membership');
  return fetch(urlString).then(function (resp) {
    if (resp.status !== 200) {
      return doCouch1(baseUrl, auth);
    } else {
      return doCouch2(baseUrl, auth, resp);
    }
  });
}
module.exports = addCors;
