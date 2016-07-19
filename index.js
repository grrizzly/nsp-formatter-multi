'use strict';

var table = require('text-table');

const header = ['*Package*', '*Version*', '*FixedIn*', '*Advisory*'];

module.exports = function(err, data, pkgPath) {
    if (err) {
        return 'Debug output: ' + JSON.stringify(Buffer.isBuffer(data) ? data.toString() : data) + '\n' + err;
    }

    if (!data.length) {
        return `(+) Zero Vulnerabilities Found`;
    }

    return format(data);
};

function format(data) {
    const tableData = [header];
    const rows = data.map((advisory) => {
        return [
            advisory.module,
            advisory.vulnerable_versions,
            advisory.patched_versions,
            `<${advisory.advisory}|${advisory.id}>`,
            `\n_${advisory.path.join('>')}_`
        ];
    });

    const fullTable = tableData.concat(rows);
    return table(fullTable, {
        hsep: ' ',
        stringLength: (string) => {
          string = string.replace(/\*(\w*)\*/g, '$1');
          return string.length;
        }
    });
}
