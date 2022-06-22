const { JWT_SECRET } = require("../secrets");
const { findBy } = require("../users/users-model");
const jwt = require("jsonwebtoken");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  !token
    ? next({ status: 401, message: "Token required" })
    : jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
        err
          ? next({ status: 401, message: "Token invalid" })
          : (req.decodedToken = decodedToken);
        next();
      });
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
};

const only = (role_name) => (req, res, next) => {
  role_name === req.decodedToken.role_name
    ? next()
    : next({ status: 403, message: "This is not for you" });
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
};

const checkUsernameExists = async (req, res, next) => {
  try {
    const username = await findBy({ username: req.body.username });
    !username ? next({ status: 401, message: "Invalid credentials" }) : next();
  } catch (err) {
    next(err);
  }
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
};

const validateRoleName = (req, res, next) => {
  !req.body.role_name || !req.body.role_name
    ? (req.body.role_name = "student")
    : req.body.role_name.trim() === "admin"
    ? next({ status: 422, message: "Role name can not be admin" })
    : req.body.role_name.trim().length > 32
    ? next({
        status: 422,
        message: "Role name can not be longer than 32 chars",
      })
    : (req.role_name = req.body.role_name.trim());
  next();
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
