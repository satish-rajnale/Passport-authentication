const express = require("express");
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const passport = require('passport');

const { forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));


router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'please fill in all fields' });
    }

    if (password != password2) {
        errors.push({ msg: "Password do not match" });
    }

    if (password.length < 3) {
        errors.push({ msg: "password should be greater than 3" })
    }

    //errors
    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        })
    } else {
        //validation passed
        User.findOne({ email: email })
            .then(user => {
                if (user) {
                    //user exists
                    errors.push({ msg: "email already exists" })
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    //Hash password
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err;

                            newUser.password = hash;

                            newUser
                                .save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered')
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                        });
                    });
                }

            });

    }
});

//login handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});


module.exports = router;