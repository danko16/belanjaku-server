module.exports = function (sequelize, DataTypes) {
  const Users = sequelize.define(
    'users',
    {
      id: {
        allowNull: false,
        primaryKey: true,
        type: DataTypes.UUID,
        defaultValue: sequelize.UUIDV4,
      },
      full_name: {
        allowNull: false,
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
        allowNull: false,
        type: DataTypes.STRING,
        validate: {
          is: /^(?=.*\d)(?=.*[a-zA-Z]).{8,}$/,
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
