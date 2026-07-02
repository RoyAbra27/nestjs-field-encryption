export const TENANT_ID_RESOLVER = Symbol('TENANT_ID_RESOLVER');
export type TenantIdResolver = () => string | number;
