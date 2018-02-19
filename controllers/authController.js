const authController = require("express").Router();

// User model
const User           = require("../models/users");

// BCrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;

authController.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

authController.post("/signup", (req, res, next) => {
  var username = req.body.username;
  var userpass = req.body.password;

  // Can't leave blank username and password fields
  if (username === "" || userpass === "") {
    res.render("auth/signup", { 
      errorMessage: "Indicate a username and a password to sign up" 
    });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
  // If username already exists, too bad => can't create another one
  // with the same credentials 😁
    if (user !== null) {
      res.render("auth/signup", { 
        errorMessage: "The username already exists" 
      });
      return;
    }

    var salt     = bcrypt.genSaltSync(bcryptSalt);
    var password = bcrypt.hashSync(userpass, salt);

    var newUser  = new User({
      username,
      password
    });

    newUser.save((err) => {
      res.redirect("/login");
    });
  });
});

authController.get("/login", (req, res, next) => {
  res.render("auth/login");
});

authController.post("/login", (req, res, next) => {
  var username = req.body.username;
  var userpass = req.body.password;

  if (username === "" || userpass === "") {
    res.render("auth/login", { 
      errorMessage: "Indicate username and password to sign up" 
    });
    return;
  }

  User.findOne({ username }, "_id username password", (err, user) => {
    if (err || !user) {
      res.render("auth/login", { 
        errorMessage: "The username doesn't exist" 
      });
    } else {
      if (bcrypt.compareSync(userpass, user.password)) {
        req.session.currentUser = user;
        res.redirect("/");
      } else {
        res.render("auth/login", { 
          errorMessage: "Incorrect password" 
        });
      }
    }
  });
});

authController.get("/logout", (req, res, next) => {
  if (!req.session.currentUser) { 
    res.redirect("/login"); 
    return; 
  }

  req.session.destroy((err) => {
    if (err) { 
      console.log(err); 
    }
    else { 
      res.redirect("/login"); 
    }
  });
});

module.exports = authController;
