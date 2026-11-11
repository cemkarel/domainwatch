import { connect } from 'node:tls';
export default {async fetch() {
  const result = await new Promise(resolve => {
    const socket = connect({host:'example.com',port:443,servername:'example.com'}, () => {
      try { resolve({expires:socket.getPeerCertificate().valid_to}); }
      catch (error) { resolve({error:String(error)}); }
      finally { socket.destroy(); }
    });
    socket.on('error', error => resolve({error:String(error)}));
    socket.setTimeout(5000, () => { resolve({error:'timeout'}); socket.destroy(); });
  });
  return Response.json(result);
}};
