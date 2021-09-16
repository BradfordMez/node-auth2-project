const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token)
    return next({
      status: 401,
      message: "Token required",
    });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return next({
        status: 401,
        message: "Token invalid",
      });
    req.decodedJwt = decoded;
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
  const { decodedJwt } = req;
  // console.log('JESUS HAS ABANDONED US',req)
  if (decodedJwt.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" });
  }
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
    const users = await Users.findBy({ username: req.body.username });

    if (!users.length) {
      next({ status: 401, message: "Invalid credentials" });
    } else {
      req.user = users[0];
      next();
    }
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
  try {
    if (!req.body.role_name || !req.body.role_name.trim()){
      req.role_name = 'student'
      next()
    }else if (req.body.role_name.trim() === 'admin'){
      next({status:422, message: 'Role name can not be admin'})
    }else if (req.body.role_name.trim().length > 32){
      next({status:422, message: 'Role name can not be longer than 32 chars'})
    }else if (req.body.role_name.trim() === 'instructor'){
      req.role_name = 'instructor'
      next()
    }else{
      req.role_name = req.role_name.trim()
      req.role_id = req.role_id.increments()
      next()
    }
  } catch (err) {
    next(err);
  }

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
