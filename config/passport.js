const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// load user model

const User = require('../models/User');

module.exports = function(passport){
    passport.use(
        new LocalStrategy({usernameField: 'accountno', passwordField: 'pass'}, (accountno, pass, done)=>{
            // Match User
            console.log("here");
            User.findOne({accountNumber: accountno})
            .then((user)=> {
                if(!user){
                    return done(null, false, {message: 'Account number is not registered'});
                }
                // Match password
                bcrypt.compare(pass, user.password, (err, isMatch)=>{
                    if(err) throw err;

                    if(isMatch){
                        console.log("USER FOUND");
                        console.log(isMatch);
                        return done(null, user);
                    }
                    else{
                        return done(null, false, {message: 'Password incorrect'});
                    }
                });

            })
            .catch(err=>console.log(err));
        })
    );
    console.log("SERIALIZE");
    passport.serializeUser((user, done)=>{
        done(null, user.id);
    })

    passport.deserializeUser(function(user, done) {
        process.nextTick(function() {
          return done(null, user);
        });
      });
}