'use strict';

const fs = require('fs');
const nspDefaultOutput = require('nsp/lib/formatters/default');

const header = ['Package', 'Version', 'FixedIn', 'Advisory'];

module.exports = function(err, data, pkgPath) {
    if (err) {
        return 'Debug output: ' + JSON.stringify(Buffer.isBuffer(data) ? data.toString() : data) + '\n' + err;
    }

    if (!data.length) {
      fs.writeFileSync('slack-formatted', ':sunny: Zero Known Vulnerabilities Found');
    }else{
      writeFormatted(data);
    }

    writeRaw(data);
    return nspDefaultOutput(err, data, pkgPath);
};

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
  // yes 4 is a magic number, as we dont want to hide only 1 dependency).
  if (path.length > 4) {
    return `${path[0]} > ${path[1]} > (${path.length-3} deps) > *${path[path.length-1]}*`
  }
  return path.reduce((first, second, idx, arry) => {
    if  (idx === arry.length - 1) {
      return `${first} > *${second}*`;
    }
    return `${first} > ${second}`;
  });
}
