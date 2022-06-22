const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
// const generateToken = require('../secrets/generateToken')
const { JWT_SECRET } = require("../secrets");
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {

  const {username, password, role_name} = req.body
  const hash = bcrypt.hashSync(password, 12)
 Users.add({username, password: hash, role_name})
  .then(user => {
    res.status(201).json(user)
  })
  .catch(next)
} 
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
);


router.post("/login", checkUsernameExists, (req, res, next) => {
if(bcrypt.compareSync(req.body.password, req.user.password)){
  const token = generateToken(req.user)
  const {username} = req.user
  res.json({
    status: 200,
    message: `${username} is back!`,
    token
  })
} else {
  next({status: 401, message: 'Invalid credentials'})
}
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role_name: user.role_name,
  };

  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET,options)
}

module.exports = router;
