const io = require('socket.io')();
const uaParser = require('ua-parser-js');
const { users: User, login_activities: LoginActivity } = require('./models');

io.on('connection', (socket) => {
  const ua = uaParser(socket.handshake.headers['user-agent']);
  const address = socket.handshake.address;
  const time = new Date(socket.handshake.time);

  socket.on('login', async ({ userId }) => {
    if (userId) {
      const user = await User.findOne({
        where: { id: userId },
        include: {
          model: LoginActivity,
          where: {
            ip_address: address,
          },
          required: false,
        },
      });
      if (user) {
        const logPayload = {
          os: ua.os.name,
          browser: ua.browser.name,
          device_vendor: ua.device.vendor,
          device_model: ua.device.model,
          device_type: ua.device.type,
          cpu: ua.cpu.architecture,
          ip_address: address,
          location: null, //to do use ip location api
          last_active: time,
        };
        if (!user.login_activities.length) {
          await LoginActivity.create({
            user_id: user.id,
            ...logPayload,
          });
        } else {
          await LoginActivity.update(logPayload, {
            where: {
              user_id: user.id,
            },
          });
        }

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
