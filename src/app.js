import 'dotenv/config.js';

import { Strategy } from '@node-saml/passport-saml';
import express from 'express';
import session from 'express-session';
import * as fs from 'fs';
import passport from 'passport';
import { prettyPrintJson } from 'pretty-print-json';
import { URL } from 'url';

const __dirname = new URL('.', import.meta.url).pathname;

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Passport SAML strategy configuration
passport.use(
  'saml',
  new Strategy(
    {
      issuer: process.env.IDP_AUDIENCE,
      path: '/login/callback',
      // URL that goes from the Service Provider -> Identity Provider
      entryPoint: process.env.IDP_ENTRYPOINT,
      cert: fs.readFileSync(__dirname + '../cert/cert.pem', 'utf8')
    },
    (profile, done) => {
      return done(null, profile);
    }
  )
);

const app = express();

// Express middleware for parsing incoming requests
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Express session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
  })
);

// Use Passport
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  else return res.redirect('/login');
}

app.get('/', ensureAuthenticated, function (req, res) {
  res.send(
    `<h1>Hello, ${
      req.user.preferredUsername
    }</h1><p>This is a summary of provided data:</p>
    <pre id=account class=json-container>${prettyPrintJson.toHtml(
      req.user
    )}</pre><a href="/logout">Logout</a> (You still need to invalidate session in IAM Identity Center)`
  );
});

app.get(
  '/login',
  passport.authenticate('saml', {
    failureRedirect: '/login/fail',
    failureFlash: true
  }),
  function (req, res) {
    res.redirect('/');
  }
);

app.get('/login/fail', function (req, res) {
  res.status(401).send('Login failed');
});

// Route for handling SAML callback
app.post(
  '/login/callback',
  passport.authenticate('saml', {
    failureRedirect: '/',
    failureFlash: true
  }),
  (req, res) => {
    res.redirect('/');
  }
);

// Route for logging out
// https://stackoverflow.com/questions/72336177/error-reqlogout-requires-a-callback-function
app.get('/logout', function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    // You still need to invalidate session in IAM Identity Center
    res.redirect('/');
  });
});

// Start the server
const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
