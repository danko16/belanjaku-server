module.exports = function (sequelize, DataTypes) {
  const LoginActivities = sequelize.define(
    'login_activities',
    {
      id: {
        allowNull: false,
        primaryKey: true,
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
      },
      user_id: {
        allowNull: false,
        foreignKey: true,
        type: DataTypes.UUID,
        references: {
          models: 'users',
          key: 'id',
        },
      },
      browser: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      os: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      device_vendor: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      device_model: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      device_type: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      cpu: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      ip_address: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      location: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      last_active: {
        allowNull: false,
        type: DataTypes.DATE,
      },
    },
    { timestamps: true, underscored: true }
  );

  LoginActivities.associate = function (models) {
    LoginActivities.belongsTo(models.users, {
      foreignKey: 'user_id',
    });
  };

  return LoginActivities;
};
