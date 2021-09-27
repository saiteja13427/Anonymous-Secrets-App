//jshint esversion:6


//Requirements
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passpostLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


//Mongo connection
mongoose.connect("mongodb://localhost:27017/secretsDB", { useNewUrlParser: true });

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));

//Setting public folder to serve css, js and images
app.use(express.static("public"));

app.set("view engine", "ejs");

app.use(session({
    secret: 'This Is A Secret',
    resave: false,
    saveUninitialized: true,
  }))

  app.use(passport.initialize());
  app.use(passport.session());

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passpostLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
  
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "http://googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {            //Callback from google
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
})

app.route("/login")
    .get(function(req, res){
        res.render("login");
    })
    .post(function(req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        req.login(user, function(err) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                })
            }
        })
    })

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })
    .post(function(req, res) {
        //Here as it is username, the field name in html also should be username otherwise it doesn't work!!
        User.register({username: req.body.username}, req.body.password, function(err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                })
            }
        })

    })

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
})   

app.get("/secrets", function (req, res) {
    User.find({"secret": {$ne: null}}, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers})
            }
        }
    })

        
})    

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    }else{
        res.redirect("/login");
    }
    
})    

app.post("/submit", function (req, res) {
    const secret = req.body.secret;
    User.findById(req.user._id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = secret;
                foundUser.save();
                res.redirect("/secrets")
            }
        }
    })
})    


app.get("/auth/google",
  passport.authenticate("google", { scope:
      [ "email", "profile" ] }
));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }); 
app.listen(3000, function(err){
    if (err) {
        console.log(err);
    } else {
        console.log("Server running at 3000");
    }
})


