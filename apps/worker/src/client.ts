/**
 * Hosted browser SDK served at /auth2c.js.
 *
 * Security invariants enforced here:
 *  - The OAuth transaction record stores the verifier, state, the exact
 *    redirect URI, and the return destination.
 *  - During callback, state is verified and the current URL must correspond to
 *    the stored redirect URI after removing only the broker-added `code` and
 *    `state` query parameters. The exact stored redirect URI (including any
 *    legitimate pre-existing query parameters) is sent to /token.
 *  - signOut() is async: it attempts /session/revoke, clears local identity in
 *    a finally block, emits auth2c:change, and resolves after the remote
 *    attempt (success or failure).
 *
 * Decoded browser claims are display-only; authoritative revocation requires
 * /session/check on the server.
 */
export const browserClient = `(function(g){"use strict";var KEY="auth2c.identity",TX="auth2c.transaction",pending=null;function b64(b){return btoa(String.fromCharCode.apply(null,new Uint8Array(b))).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"")}function rand(n){var a=new Uint8Array(n);crypto.getRandomValues(a);return b64(a)}async function challenge(v){return b64(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v)))}function config(){var s=document.currentScript||document.querySelector("script[src*='auth2c.js']");return {base:s&&s.src?new URL(s.src).origin:location.origin,callback:location.origin+location.pathname}}function decode(token){var s=token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var raw=atob(s),bytes=new Uint8Array(raw.length);for(var i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);return JSON.parse(new TextDecoder().decode(bytes))}
async function signIn(o){o=o||{};var c=config(),v=rand(48),state=rand(24),redirect=o.redirectUri||c.callback;sessionStorage.setItem(TX,JSON.stringify({v:v,state:state,redirectUri:redirect,returnTo:o.returnTo||location.pathname+location.search}));var u=new URL(c.base+"/authorize");u.searchParams.set("redirect_uri",redirect);u.searchParams.set("code_challenge",await challenge(v));u.searchParams.set("code_challenge_method","S256");u.searchParams.set("state",state);if(o.requestProfile)u.searchParams.set("scope","openid email profile");location.assign(u)}
async function runCallback(){var u=new URL(location.href),code=u.searchParams.get("code");if(!code)return get();var t=JSON.parse(sessionStorage.getItem(TX)||"null");if(!t||t.state!==u.searchParams.get("state"))throw Error("Invalid OAuth state");
// Verify the current URL corresponds to the stored redirect URI after removing
// only the broker-added code/state params. Send the exact stored redirect URI
// to /token so legitimate pre-existing query params are preserved.
var stored=new URL(t.redirectUri,location.origin);if(stored.origin!==u.origin||stored.pathname!==u.pathname)throw Error("Callback path mismatch");
var sp=new URLSearchParams(stored.search);for(var k of["code","state"])u.searchParams.delete(k);var leftover=new URLSearchParams(u.search);leftover.sort();var base=new URLSearchParams(stored.search);base.sort();if(leftover.toString()!==base.toString())throw Error("Callback query mismatch");
var c=config(),r=await fetch(c.base+"/token",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code:code,code_verifier:t.v,redirect_uri:t.redirectUri})});var x=await r.json();if(!r.ok)throw Error(x.error||"Token exchange failed");
var p=decode(x.id_token),id={userId:p.sub,token:x.id_token,email:p.email||null,name:p.name||null,picture:p.picture||null,expiresAt:p.exp*1000};localStorage.setItem(KEY,JSON.stringify(id));sessionStorage.removeItem(TX);history.replaceState({},"",t.returnTo||"/");dispatchEvent(new CustomEvent("auth2c:change",{detail:id}));return id}
function callback(){if(!pending)pending=runCallback().finally(function(){pending=null});return pending}
function get(){try{var x=JSON.parse(localStorage.getItem(KEY)||"null");return x&&x.expiresAt>Date.now()?x:null}catch(_){return null}}
function clearLocal(){localStorage.removeItem(KEY);dispatchEvent(new CustomEvent("auth2c:change",{detail:null}))}
async function out(){var x=get();try{if(x)await fetch(config().base+"/session/revoke",{method:"POST",headers:{authorization:"Bearer "+x.token}})}catch(_){}finally{clearLocal()}}
async function check(){var x=get();if(!x)return false;var r=await fetch(config().base+"/session/check",{method:"POST",headers:{authorization:"Bearer "+x.token}});if(!r.ok)clearLocal();return r.ok}
g.Auth2C={signIn:signIn,handleCallback:callback,getIdentity:get,signOut:out,checkSession:check};if(new URL(location.href).searchParams.has("code"))callback().catch(function(e){console.error("Auth2C callback failed",e)})})(window);`;
