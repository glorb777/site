import { vaultHandler,settings,failure } from '../lib/core.mjs';
import { storeFor } from '../lib/store.mjs';
export default async function handler(request,context){try{return await vaultHandler(request,storeFor(context),settings());}catch(error){return failure(error);}}
export const config={path:'/api/vault'};
