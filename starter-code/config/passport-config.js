const passport = require('passport');


const User = require('../models/user.js');

// "serializeUser" is called when the user logs in
passport.serializeUser((userFromDb, done) => {
    done(null, userFromDb._id);

});


passport.deserializeUser((idFromBowl, done) => {

    User.findById(
      idFromBowl,

      (err, userFromDb) => {
          if (err) {
              done(err);
              return;
          }
          // give passport the user document from the database
          //              |
          done(null, userFromDb);
      }
    )
});

const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

passport.use(
  new LocalStrategy(
    // 1st arg -> settings object
    {
        usernameField: 'loginUser',
        passwordField: 'loginPassword'
    },



    // 2nd arg -> callback
    (usernameValue, passValue, done) => {
      User.findOne(
        {username: usernameValue},

        (err, userFromDb) => {
           if (err) {
             done (err);
             return;
           }
          // "userFromDb" will be "null" if we didn't find Anything
           if(userFromDb === null) {
              done( null, false, {message: 'Email is wrong. 💩'});
              return;
           }
           console.log(passValue);
           console.log(userFromDb);
          //  console.log(userFromDb);

            // confirm that the password is correct
            const isGoodPassword = bcrypt.compareSync(passValue, userFromDb.encryptedPassword);
            // const isGoodPassword = true;

            if(isGoodPassword === false) {
              console.log('password bad');
               done( null, false, {message: 'Email is wrong. 💩'});
               return;
            }
            // if everything works!!!!!!!send passport the user document
            done(null,userFromDb);
            // passport take "userFromDb" and calles "serializeUser"
        }
      );
    }
  )
);
