const io = require('socket.io')();
const { users: User } = require('./models');

io.on('connection', (socket) => {
  socket.on('login', async ({ userId }) => {
    if (userId) {
      const user = await User.findOne({ where: { id: userId } });
      if (user) {
        await user.update({ is_online: true });
        socket.userId = user.id;
        socket.emit('login');
      }
    }
  });

  socket.on('logout', async () => {
    const { userId } = socket;
    if (userId) {
      const user = await User.findOne({ where: { id: userId } });
      if (user) {
        await user.update({ is_online: false });
        socket.emit('logout');
      }
    }
  });

  socket.on('disconnect', async () => {
    const { userId } = socket;
    if (userId) {
      const user = await User.findOne({ where: { id: userId } });
      if (user) {
        await user.update({ is_online: false });
      }
    }
  });
});

module.exports = io;
