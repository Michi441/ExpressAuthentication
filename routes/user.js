var express = require('express');
var router = express.Router();


var User = require('../models/user');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use('local.signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, function (email, password, done) {

    User.findOne({
        'email': email
    }, function (err, user) {


        if (err) {
            return done(err);
        }

        if (user) {

            return done(null, false, {
                message: 'Email already in use'
            })
        }

        var newUser = new User();

        newUser.email = email;
        newUser.password = newUser.securePassword(password);
        newUser.save(function (err, user) {


            if (err) {

                return done(err)
            }

            return done(null, user);
        })
    })
}))

passport.use('local.signin', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'

}, function (email, password, done) {

    User.findOne({
        'email': email
    }, function (err, user) {

        if (err) {
            return done(err)
        }


        if (!user || !user.verifyPassword(password)) {

            return done(null, false, {
                message: 'No user found with email adress / password'
            })
        }

        return done(null, user);
    })
}))

router.get('/signin', notLoggedIn, function (req, res, next) {
    res.render('user/signin');
});

router.post('/signin', passport.authenticate('local.signin', {

    successRedirect: '/user/profile',
    failureRedirect: '/user/signin'
}))


router.get('/signup', notLoggedIn, function (req, res, next) {
    res.render('user/signup');
});

router.post('/signup', passport.authenticate('local.signup', {

    successRedirect: '/user/profile',
    failureRedirect: '/user/signup'
}))

router.get('/profile', isLoggedIn, function (req, res, next) {
    res.render('user/profile', {
        user: req.user
    });
});

router.get('/signout', function (req, res) {
    req.logout();
    res.redirect('/');
});





function isLoggedIn(req, res, next) {


    if (req.isAuthenticated()) {

        next();
    }

    res.redirect('/')
}

function notLoggedIn(req, res, next) {


    if (!req.isAuthenticated()) {

        next();
    }

    res.redirect('/')
}



module.exports = router;