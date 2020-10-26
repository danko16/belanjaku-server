module.exports = function (sequelize, DataTypes) {
  const Users = sequelize.define(
    'users',
    {
      id: {
        allowNull: false,
        primaryKey: true,
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
      },
      full_name: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      birthday: {
        allowNull: true,
        type: DataTypes.DATE,
      },
      gender: {
        allowNull: true,
        type: DataTypes.STRING,
      },
      email: {
        allowNull: true,
        type: DataTypes.STRING,
        unique: true,
        validate: {
          isEmail: true,
        },
      },
      phone: {
        allowNull: true,
        type: DataTypes.STRING,
        unique: true,
        validate: {
          is: /^(0|\+?62)?[0-9]{11}$/,
        },
      },
      password: {
        allowNull: true,
        type: DataTypes.STRING,
        validate: {
          is: /^.{8,}$/,
        },
      },
      login_attempt: {
        allowNull: false,
        type: DataTypes.INTEGER,
        defaultValue: 0,
      },
      is_online: {
        allowNull: false,
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
    },
    { timestamps: true, underscored: true }
  );

  return Users;
};
