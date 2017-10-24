const express        = require("express");
const router         = express.Router();
// User model
const User           = require("../models/user");
// Bcrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;
const ensureLogin = require("connect-ensure-login");
const passport      = require("passport");



router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});


router.get('/signup', (req, res , next) => {
  res.render('./passport/signup.ejs');
});


router.post('/signup', (req, res, next) => {
  if(req.body.signupUser === "" || req.body.signupPassword === ""){
      res.locals.feedbackMessage = 'We need both email and password.'
      res.render('./passport/signup.ejs');
      return;
    }

    User.findOne(
      { username: req.body.signupUser },

      (err, userFromDb) => {
        if(err) {
          next(err);
          return;
        }

    //"user fromDB" will be "null" if we didn't find anything

    if (userFromDb){
      res.locals.feedbackMessage = 'Username Taken.'
      res.render('./passport/signup.ejs');
      return;
    }
    //if we get to this line we can save!
    const salt = bcrypt.genSaltSync(10);
    const scrambledPass = bcrypt.hashSync(req.body.signupPassword, salt);

    const theUser = new User ({
        username: req.body.signupUser,
        encryptedPassword: scrambledPass
        // password: req.body.signupPassword
    });
    theUser.save((err) => {
      if (err){
        next(err);
        return;
      }

      // console.log(theUser);
      req.flash('signupSuccess', 'Sign up successful! Try logging in.')
      res.redirect('/');
    });
  }
); // UserModel.findOne()
});

router.get('/login', (req,res, next) => {
  // check for feedback messages from the log in process
  res.locals.flashError = req.flash('error');

  //check for feedback messages from the log out process
  res.locals.logoutFeedback = req.flash('logoutSuccess');

  res.render('./passport/login.ejs');
});

router.post('/login',
            passport.authenticate
      ('local', {
        successRedirect:'/',
        failureRedirect: '/login',
        failureFlash: true}
      )
);



module.exports = router;
