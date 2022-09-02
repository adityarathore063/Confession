//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

//public file access
app.use(express.static("public"));
//ejs files access
app.set('view engine', 'ejs');
//body-parser access
app.use(bodyParser.urlencoded({extended: true}));

//express-session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//initialize session
app.use(passport.initialize());
app.use(passport.session());

//mongodb atlas connection
mongoose.connect(process.env.DB_CONNECT_STRING, { useNewUrlParser: true, useUnifiedTopology: true });

//mongoose schema
const userScheme = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

//passportLocalMongoose
userScheme.plugin(passportLocalMongoose);
userScheme.plugin(findOrCreate);

// mongoose model
const User = new mongoose.model("User", userScheme);

//create strategy instaed of authenticate
passport.use(User.createStrategy());

//serialize and deserialize in passport
passport.serializeUser(function(user, done){
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err, user);
  });
});

// configure strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://confession-page.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FB_CLIENT_ID,
    clientSecret: process.env.FB_CLIENT_SECRET,
    callbackURL: "https://confession-page.herokuapp.com/auth/facebook/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

//authenticate google and facebook request
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"]})
);
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else{
      if (foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers})
      }
    }
  })
});
app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});


app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res) {
  res.redirect("/");
});

app.post("/register", function(req, res) {
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});
app.post("/login", function(req, res) {
  const user = new User({username: req.body.username,
    password: req.body.password});

  req.login(user, function(err) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(process.env.PORT || 3000, function(req, res) {
  console.log("Server started on port 3000");
});
