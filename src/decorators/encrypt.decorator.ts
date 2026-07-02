export const Encrypt = (): PropertyDecorator => {
  return (target, propertyKey) => {
    Reflect.defineMetadata('encrypt', true, target, propertyKey);
  };
};
