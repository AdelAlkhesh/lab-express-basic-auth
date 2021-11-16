const router = require("express").Router();
const UserModel = require("../models/User.model");
const bcrypt = require("bcryptjs");

router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      next(err);
    });
});

router.get("/signin", (req, res, next) => {
  res.render("auth/signin.hbs");
});

router.post("/signin", (req, res, next) => {
  const { username, password } = req.body;
  UserModel.find({ username })
    .then((data) => {
      if (data.length) {
        let userObj = data[0];

        let isMatching = bcrypt.compareSync(password, userObj.password);
        if (isMatching) {
          req.session.info = userObj;
          res.redirect("/profile");
        } else {
          res.render("auth/signin.hbs", { error: "Password not matching"});
          return;
        }
      } else {
        res.render("auth/signin.hbs", { error: "Invalid Username" });
        return;
      }
    })
    .catch((err) => {
      next(err);
    });
});

const checkLogIn = (req, res, next) => {
  if (req.session.info) {
    //invokes the next available function
    next();
  } else {
    res.redirect("/signin");
  }
};

router.get("/profile", checkLogIn, (req, res, next) => {
  let userInfo = req.session.info;
  res.render("auth/profile.hbs", { username: userInfo.username });
});

router.get("/main", checkLogIn, (req, res, next) => {
  res.render("auth/main.hbs");
});

router.get("/private", checkLogIn, (req, res, next) => {
  res.render("auth/private.hbs");
});

module.exports = router;
