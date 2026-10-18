import { getStore } from '@netlify/blobs';
export function storeFor(context){
  const deploy=context?.deploy?.context;
  // Preview deployments have their own namespace; a preview cannot overwrite the live notebook.
  const name=deploy==='production'?'vetvi-private-v1':`vetvi-preview-${context?.deploy?.id||'local'}`;
  return getStore({name,consistency:'strong'});
}
