import { loginHandler,settings,failure } from '../lib/core.mjs';
import { storeFor } from '../lib/store.mjs';
export default async function handler(request,context){try{return await loginHandler(request,storeFor(context),settings(),context.ip);}catch(error){return failure(error);}}
export const config={path:'/api/login',rateLimit:{action:'rate_limit',windowLimit:15,windowSize:60,aggregateBy:['ip','domain']}};
