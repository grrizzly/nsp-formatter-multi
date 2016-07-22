'use strict';

const table = require('text-table');
const fs = require('fs');
const nspDefaultOutput = require('nsp/lib/formatters/defaul');

const header = ['*Package*', '*Version*', '*FixedIn*', '*Advisory*'];

module.exports = function(err, data, pkgPath) {
    if (err) {
        return 'Debug output: ' + JSON.stringify(Buffer.isBuffer(data) ? data.toString() : data) + '\n' + err;
    }

    if (!data.length) {
        return `:sunny: Zero Known Vulnerabilities Found`;
    }

    writeFormatted(data);
    writeRaw(data);
    return nspDefaultOutput(err, data, pkgPath);
};

function writeFormatted(data) {
    const tableData = [header];
    const rows = data.map((advisory) => {
        return [
            `*${advisory.module}*`,
            advisory.vulnerable_versions,
            advisory.patched_versions,
            `<${advisory.advisory}|${advisory.id}>`,
            `\n_${pathBuilder(advisory.path)}_`
        ];
    });

    const fullTable = tableData.concat(rows);
    const formattedTable = table(fullTable, {
        hsep: ' ',
        stringLength: (string) => {
            string = string.replace(/\*(\w*)\*/g, '$1');
            return string.length;
        }
    });
    return fs.writeFileSync('slack-formatted', formattedTable);
}

function writeRaw(data) {
    return fs.writeFileSync('nsp-audit.json', JSON.stringify(data));
}

function pathBuilder(path) {
    return `${path[0]} > (${path.length-2} deps) > ${path[path.length-1]}`
}
