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
  {
    path: '/_config/httpd/require_valid_user',
    value: '"true"'
  },
  {
    path: '/' + database + '/_security',
    value: JSON.stringify({
      'members': {
        'roles': roles
      }
    })
  },
  {
    path: '/' + database + '/_design/only_staffs',
    value: JSON.stringify({
      validate_doc_update: validator.toString()
    })
  }
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
