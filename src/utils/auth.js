const { checkToken } = require('./token');
const { users: User } = require('../models');

const isAllow = async (req, res, next) => {
  let token = req.headers['x-token'];
  if (!token) {
    return res.status(401).json({ status: 401, message: 'Sorry, Authentication required! :(' });
  }
  try {
    token = token.split(' ')[1];
    if (!token) return res.status(401).json({ status: 401, message: 'Invalid Token!' });

    const payload = await checkToken(token, 'login');

    if (!payload) return res.status(401).json({ status: 401, message: 'Invalid Token!' });

    let { uid, type } = payload;

    if (!type) return res.status(401).json({ status: 401, message: 'User Type not Present!' });

    let user;
    if (type === 'user') {
      user = await User.findOne({ where: { id: uid } });
    }

    if (!user) {
      return res.status(401).json({ status: 401, message: 'User not found!' });
    }

    res.locals.user = {
      id: user.id,
      type,
      email: user.email,
      phone: user.phone,
    };

    next();
  } catch (error) {
    return res.status(401).json({ status: 401, message: 'Something Wrong!', error });
  }
};

module.exports = Object.freeze({ isAllow });
