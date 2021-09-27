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

//Passport local mongoose plugin to simplify username password login with passport
userSchema.plugin(passpostLocalMongoose);

//A plugin to make findOrCreate function work in the google strategy
userSchema.plugin(findOrCreate);


//Creating model
const User = new mongoose.model("User", userSchema);

//The local strategy for register and login with username and password
passport.use(User.createStrategy());

//Serializing and deserializing users for all the auth strategies
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
  
//Google auth strategy  
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


//Get and post got login route
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
                //Authenticating and storing session cookies using passport
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                })
            }
        })
    })

//Get and post for register route
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

//Logout
app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
})   

//Get for secrets route to render all the secrets
app.get("/secrets", function (req, res) {
    //{$ne: null} for finding all the users who have secrets
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

//Get and post for submit route
app.route("/submit")
.get(function (req, res) {
    //Checking is user is authenticated
    if (req.isAuthenticated()) {
        res.render("submit");
    }else{
        res.redirect("/login");
    }
    
}) 
.post(function (req, res) {
    const secret = req.body.secret;
    //Finding logedin users id from req.user._id (the id is stored in req by passport)
    User.findById(req.user._id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            //Saving secrets into secret field of that user
            if (foundUser) {
                foundUser.secret = secret;
                foundUser.save();
                res.redirect("/secrets")
            }
        }
    })
})    

//The auth route for google which is called once google auth button is clicked
app.get("/auth/google",
  passport.authenticate("google", { scope:
      [ "email", "profile" ] }
));


//The redirect uri for google auth
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


