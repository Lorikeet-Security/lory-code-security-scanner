// Express handlers with the usual mistakes. Fixture only.
const express = require("express");
const { exec } = require("child_process");

const app = express();

// A provider-shaped key would be rejected by GitHub push protection on the
// way into this repository, so this fixture uses a generic one — caught by
// the entropy detector rather than by a vendor rule.
const SESSION_SECRET = "Zx9Qw3Rt7Yu1Pa5Sd8Fg2Hj4Kl6Mn0Bv";

app.get("/search", (req, res) => {
  db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`, (err, rows) => {
    res.send(`<h1>Results for ${req.query.q}</h1>`);
  });
});

app.get("/logs", (req, res) => {
  exec(`tail -n 100 /var/log/${req.query.file}`, (err, out) => res.send(out));
});

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

function makeSessionToken() {
  return Math.random().toString(36).slice(2);
}

document.getElementById("out").innerHTML = location.hash.slice(1);
