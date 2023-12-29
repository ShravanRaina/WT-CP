require('dotenv').config();
const express = require("express");
const bodyParser = require('body-parser');
const ejs = require("ejs");
const  _ = require("lodash");
const mongoose = require("mongoose");
const { log, error } = require('console');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
const {ensureAuthenticated} = require('./config/auth');

var account;
const app = express();

require('./config/passport')(passport);

mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true})
.then(()=> console.log("Mongodb connected..."))
.catch(err=> console.log(err));

// User Model
const User = require('./models/User');
// const passport = require('./config/passport');

app.set('view engine', 'ejs');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// Express session
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true,
    cookie:{_expires : 120000} // The session expires after 2 minutes
  }));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
app.use(flash());

// Global vars
app.use((req, res, next)=>{
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
})

app.use(express.static("public"));

// BASIC 

app.get("/", (req, res)=>{
    res.render("register");
});

app.get("/login", (req, res)=>{
    res.render("login");
})

app.post('/login', (req, res, next)=>{
    account = req.body.accountno;
    passport.authenticate('local', {
        successRedirect: '/home',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next)
});

app.post('/register', (req, res)=>{
    // console.log(req.body);
    const {name, email, accountno, pass, conpass} = req.body;

    let errors = [];

    // Check required fields
    if(!name || !email || !pass || !conpass || !accountno){
        errors.push({msg: 'Please fill in all fields'});
    }

    // Check pass match
    if(pass != conpass){
        errors.push({msg: 'Passwords do not match'});
    }

    if(accountno.length<8){
        errors.push({msg: 'Not a valid Account number'});
    }
    
    // Check pass length
    if(pass.length < 6){
        errors.push({msg: 'Password should be at least 6 characters long'});
    }

    if(errors.length>0){
        res.render('register', {
            errors,
            name,
            email,
            accountno,
            pass,
            conpass
        });
    }
    else{
        // Validation passed
        User.findOne({accountNumber: accountno, email: email})
        .then(user => {
            if(user){

                // User exists
                errors.push({msg: 'User Already Exists'});
                res.render('register', {
                    errors,
                    name,
                    email,
                    accountno,
                    pass,
                    conpass
                });
            }
            else{
                const newUser = new User({
                    name: req.body.name,
                    email: req.body.email,
                    accountNumber: req.body.accountno,
                    password: req.body.pass
                });
                

                newUser.save()
                .then((user)=>{
                    console.log("User saved successfully");
                })
                .catch((err)=>{
                    errors.push({msg: 'User Already Exists'});
                    res.render('register', {
                        errors,
                        name,
                        email,
                        accountno,
                        pass,
                        conpass
                    });
                })
                
                // Hash Password
                bcrypt.genSalt(10, (err, salt)=>bcrypt.hash(newUser.password, salt, (err, hash)=>{
                    if(err) throw err;

                    // Set password to hashed 
                    newUser.password = hash;
                    // Save user
                    newUser.save()
                    .then(user =>{
                        req.flash('success_msg', 'You are now registered and can login');
                        res.redirect('/login');
                    })
                    .catch(err => console.log(err));
                }))

            }
        });
    }

});

app.get('/logout', (req, res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/login');
      });
    // req.logout();
    // req.flash('success_msg', 'You are logged out');
    // res.redirect('/login');
})

// RENDERING

app.get('/home', ensureAuthenticated , async(req, res)=>{
    var context = req.session.context;

    const userId = req.session.passport.user;

    const user = await User.findById(userId);

    res.render('home', {context: context, username: user.name});
})

// DEPOSIT MONEY
app.get('/deposit', ensureAuthenticated, async (req, res)=>{
    const userId = req.session.passport.user;

    const user = await User.findById(userId);

    res.render('deposit', {username: user.name, balance: user.balance});
})

app.post('/deposit', async(req, res)=>{

    const userId = req.session.passport.user;

    const user = await User.findById(userId);

    user.balance += parseFloat(req.body.amount);

    await user.save();

    req.session.context = "Money deposited successfully";
    res.redirect('/home');
})

// WITHDRAW MONEY
app.get('/withdraw', ensureAuthenticated, async(req, res)=>{
    const userId = req.session.passport.user;

    const user = await User.findById(userId);
    
    res.render('withdraw', {username: user.name, balance: user.balance});
})

app.post('/withdraw', async(req, res)=>{
    const userId = req.session.passport.user;

    const user = await User.findById(userId);
  
    // Check if the user has enough funds to withdraw
    if (parseFloat(req.body.amount) > user.balance) {
      req.flash('error', 'Insufficient funds');
      req.session.context = "Insufficient funds";
      return res.redirect('/home');
    }
  
    user.balance -= parseFloat(req.body.amount);
    await user.save();
    
    req.session.context = "Money withdrawn successfully";
    res.redirect('/home');
})

// MONEY TRANSFER

app.get('/transfer', ensureAuthenticated, async(req, res)=>{
    const userId = req.session.passport.user;

    const user = await User.findById(userId);
    
    res.render('moneyTransfer', {username: user.name, balance: user.balance});
})

app.post('/transfer', async(req, res)=>{

  const senderId = req.session.passport.user;

  const sender = await User.findById(senderId);

  // Get the recipient's accountno and transfer amount from the request body
  const recipientAccount = req.body.accountno;
  const transferAmount = parseFloat(req.body.amount);

  const recipient = await User.findOne({ accountNumber: recipientAccount });

  // Check if the recipient exists and is not the sender
  if (!recipient || recipient._id.equals(sender._id)) {
    req.flash('error', 'Recipient not found');
    req.session.context = "Recipient not found";
    return res.redirect('/home');
  }

  // Check if the sender has enough funds to transfer
  if (transferAmount > sender.balance) {
    req.flash('error', 'Insufficient funds');
    req.session.context = "Insufficient funds";
    return res.redirect('/home');
  }

  sender.balance -= transferAmount;
  recipient.balance += transferAmount;

  await sender.save();
  await recipient.save();

  
  req.session.context = "Money transfer successful";
  res.redirect('/home');
})

app.get('/upipayments', ensureAuthenticated, async(req, res)=>{
    const userId = req.session.passport.user;

    const user = await User.findById(userId);

    res.render('upipayments', {username: user.name, balance: user.balance});
})

app.get('/about', ensureAuthenticated, (req, res)=>{
    res.render('about');
})

app.listen(process.env.PORT || 3000, ()=>{
    console.log("Server started at port 3000");
})