'use strict';

const fs = require('fs');
const nspTableOutput = require('nsp/reporters/table');

exports.check = {};
exports.check.error = function (err, args, logger = console) {
    nspTableOutput.check.error(err, args, logger);
}

exports.check.success = function (result, args, logger = console) {
    const { data } = result;
    if (!data.length) {
      fs.writeFileSync('slack-formatted', ':sunny: Zero Known Vulnerabilities Found');
    } else {
      writeFormatted(data);
    }
    
    writeRaw(data);
    nspTableOutput.check.success(result, args, logger);
}

function writeFormatted(advisories) {
    const advisoryStrings = advisories.map(advisory => {
      const patchedString = advisory.patched_versions ? `* ${advisory.patched_versions}* is patched.` : '';
      const title = `*<${advisory.advisory}|${advisory.title}>*`;
      const versions = `${advisory.vulnerable_versions} is vulnerable. ${patchedString}`;
      return `${title}\n> ${pathBuilder(advisory.path)}\n> ${versions}`;
    });
    return fs.writeFileSync('slack-formatted', advisoryStrings.join('\n'));
}

function writeRaw(data) {
    return fs.writeFileSync('nsp-audit.json', JSON.stringify(data));
}

function pathBuilder(path) {
  path.shift(); // remove the first element as that is the source module nsp runs against.
  if (path.length > 3) {
    return `${path[0]} > (${path.length-2} deps) > *${path[path.length-1]}*`
  }
  return path.reduce((first, second, idx, arry) => {
    if  (idx === arry.length - 1) {
      return `${first} > *${second}*`;
    }
    return `${first} > ${second}`;
  });
}
