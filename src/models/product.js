module.exports = function (sequelize, DataTypes) {
  const Products = sequelize.define(
    'products',
    {
      id: {
        allowNull: false,
        primaryKey: true,
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
      },
      name: {
        allowNull: false,
        type: DataTypes.STRING,
      },
      discount_percentage: {
        allowNull: true,
        type: DataTypes.DOUBLE,
      },
      discount_nominal: {
        allowNull: true,
        type: DataTypes.INTEGER,
      },
      actual_price: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
      final_price: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
      quantity: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
      sold: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
      condition: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
      weight: {
        allowNull: false,
        type: DataTypes.INTEGER,
      },
    },
    { timestamps: true, underscored: true }
  );

  return Products;
};
