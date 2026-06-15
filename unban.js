const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('data/database.sqlite');

db.all("SELECT key FROM settings WHERE key LIKE 'banned_ip_%'", (err, rows) => {
  if (err) { console.error(err); return; }
  console.log('IPs banidos:');
  rows.forEach(r => console.log(' -', r.key.replace('banned_ip_', '')));
  if (rows.length === 0) console.log('Nenhum IP banido');
  db.close();
});
