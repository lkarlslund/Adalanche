(()=>{var $o=Object.create;var ca=Object.defineProperty;var Qo=Object.getOwnPropertyDescriptor;var Jo=Object.getOwnPropertyNames;var es=Object.getPrototypeOf,ts=Object.prototype.hasOwnProperty;var Gr=(n,a)=>()=>{try{return a||n((a={exports:{}}).exports,a),a.exports}catch(t){throw a=0,t}},ha=(n,a)=>{for(var t in a)ca(n,t,{get:a[t],enumerable:!0})},ns=(n,a,t,e)=>{if(a&&typeof a=="object"||typeof a=="function")for(let r of Jo(a))!ts.call(n,r)&&r!==t&&ca(n,r,{get:()=>a[r],enumerable:!(e=Qo(a,r))||e.enumerable});return n};var Se=(n,a,t)=>(t=n!=null?$o(es(n)):{},ns(a||!n||!n.__esModule?ca(t,"default",{value:n,enumerable:!0}):t,n));var Ze=Gr((Wd,ma)=>{"use strict";var ct=typeof Reflect=="object"?Reflect:null,Xr=ct&&typeof ct.apply=="function"?ct.apply:function(a,t,e){return Function.prototype.apply.call(a,t,e)},xn;ct&&typeof ct.ownKeys=="function"?xn=ct.ownKeys:Object.getOwnPropertySymbols?xn=function(a){return Object.getOwnPropertyNames(a).concat(Object.getOwnPropertySymbols(a))}:xn=function(a){return Object.getOwnPropertyNames(a)};function gs(n){console&&console.warn&&console.warn(n)}var qr=Number.isNaN||function(a){return a!==a};function $(){$.init.call(this)}ma.exports=$;ma.exports.once=bs;$.EventEmitter=$;$.prototype._events=void 0;$.prototype._eventsCount=0;$.prototype._maxListeners=void 0;var jr=10;function yn(n){if(typeof n!="function")throw new TypeError('The "listener" argument must be of type Function. Received type '+typeof n)}Object.defineProperty($,"defaultMaxListeners",{enumerable:!0,get:function(){return jr},set:function(n){if(typeof n!="number"||n<0||qr(n))throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received '+n+".");jr=n}});$.init=function(){(this._events===void 0||this._events===Object.getPrototypeOf(this)._events)&&(this._events=Object.create(null),this._eventsCount=0),this._maxListeners=this._maxListeners||void 0};$.prototype.setMaxListeners=function(a){if(typeof a!="number"||a<0||qr(a))throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received '+a+".");return this._maxListeners=a,this};function Yr(n){return n._maxListeners===void 0?$.defaultMaxListeners:n._maxListeners}$.prototype.getMaxListeners=function(){return Yr(this)};$.prototype.emit=function(a){for(var t=[],e=1;e<arguments.length;e++)t.push(arguments[e]);var r=a==="error",i=this._events;if(i!==void 0)r=r&&i.error===void 0;else if(!r)return!1;if(r){var o;if(t.length>0&&(o=t[0]),o instanceof Error)throw o;var s=new Error("Unhandled error."+(o?" ("+o.message+")":""));throw s.context=o,s}var l=i[a];if(l===void 0)return!1;if(typeof l=="function")Xr(l,this,t);else for(var u=l.length,d=Jr(l,u),e=0;e<u;++e)Xr(d[e],this,t);return!0};function Kr(n,a,t,e){var r,i,o;if(yn(t),i=n._events,i===void 0?(i=n._events=Object.create(null),n._eventsCount=0):(i.newListener!==void 0&&(n.emit("newListener",a,t.listener?t.listener:t),i=n._events),o=i[a]),o===void 0)o=i[a]=t,++n._eventsCount;else if(typeof o=="function"?o=i[a]=e?[t,o]:[o,t]:e?o.unshift(t):o.push(t),r=Yr(n),r>0&&o.length>r&&!o.warned){o.warned=!0;var s=new Error("Possible EventEmitter memory leak detected. "+o.length+" "+String(a)+" listeners added. Use emitter.setMaxListeners() to increase limit");s.name="MaxListenersExceededWarning",s.emitter=n,s.type=a,s.count=o.length,gs(s)}return n}$.prototype.addListener=function(a,t){return Kr(this,a,t,!1)};$.prototype.on=$.prototype.addListener;$.prototype.prependListener=function(a,t){return Kr(this,a,t,!0)};function vs(){if(!this.fired)return this.target.removeListener(this.type,this.wrapFn),this.fired=!0,arguments.length===0?this.listener.call(this.target):this.listener.apply(this.target,arguments)}function Zr(n,a,t){var e={fired:!1,wrapFn:void 0,target:n,type:a,listener:t},r=vs.bind(e);return r.listener=t,e.wrapFn=r,r}$.prototype.once=function(a,t){return yn(t),this.on(a,Zr(this,a,t)),this};$.prototype.prependOnceListener=function(a,t){return yn(t),this.prependListener(a,Zr(this,a,t)),this};$.prototype.removeListener=function(a,t){var e,r,i,o,s;if(yn(t),r=this._events,r===void 0)return this;if(e=r[a],e===void 0)return this;if(e===t||e.listener===t)--this._eventsCount===0?this._events=Object.create(null):(delete r[a],r.removeListener&&this.emit("removeListener",a,e.listener||t));else if(typeof e!="function"){for(i=-1,o=e.length-1;o>=0;o--)if(e[o]===t||e[o].listener===t){s=e[o].listener,i=o;break}if(i<0)return this;i===0?e.shift():ms(e,i),e.length===1&&(r[a]=e[0]),r.removeListener!==void 0&&this.emit("removeListener",a,s||t)}return this};$.prototype.off=$.prototype.removeListener;$.prototype.removeAllListeners=function(a){var t,e,r;if(e=this._events,e===void 0)return this;if(e.removeListener===void 0)return arguments.length===0?(this._events=Object.create(null),this._eventsCount=0):e[a]!==void 0&&(--this._eventsCount===0?this._events=Object.create(null):delete e[a]),this;if(arguments.length===0){var i=Object.keys(e),o;for(r=0;r<i.length;++r)o=i[r],o!=="removeListener"&&this.removeAllListeners(o);return this.removeAllListeners("removeListener"),this._events=Object.create(null),this._eventsCount=0,this}if(t=e[a],typeof t=="function")this.removeListener(a,t);else if(t!==void 0)for(r=t.length-1;r>=0;r--)this.removeListener(a,t[r]);return this};function $r(n,a,t){var e=n._events;if(e===void 0)return[];var r=e[a];return r===void 0?[]:typeof r=="function"?t?[r.listener||r]:[r]:t?ps(r):Jr(r,r.length)}$.prototype.listeners=function(a){return $r(this,a,!0)};$.prototype.rawListeners=function(a){return $r(this,a,!1)};$.listenerCount=function(n,a){return typeof n.listenerCount=="function"?n.listenerCount(a):Qr.call(n,a)};$.prototype.listenerCount=Qr;function Qr(n){var a=this._events;if(a!==void 0){var t=a[n];if(typeof t=="function")return 1;if(t!==void 0)return t.length}return 0}$.prototype.eventNames=function(){return this._eventsCount>0?xn(this._events):[]};function Jr(n,a){for(var t=new Array(a),e=0;e<a;++e)t[e]=n[e];return t}function ms(n,a){for(;a+1<n.length;a++)n[a]=n[a+1];n.pop()}function ps(n){for(var a=new Array(n.length),t=0;t<a.length;++t)a[t]=n[t].listener||n[t];return a}function bs(n,a){return new Promise(function(t,e){function r(o){n.removeListener(a,i),e(o)}function i(){typeof n.removeListener=="function"&&n.removeListener("error",r),t([].slice.call(arguments))}ei(n,a,i,{once:!0}),a!=="error"&&xs(n,r,{once:!0})})}function xs(n,a,t){typeof n.on=="function"&&ei(n,"error",a,t)}function ei(n,a,t,e){if(typeof n.on=="function")e.once?n.once(a,t):n.on(a,t);else if(typeof n.addEventListener=="function")n.addEventListener(a,function r(i){e.once&&n.removeEventListener(a,r),t(i)});else throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type '+typeof n)}});var An=Gr(($d,xi)=>{xi.exports=function(a){return a!==null&&typeof a=="object"&&typeof a.addUndirectedEdgeWithKey=="function"&&typeof a.dropNode=="function"&&typeof a.multi=="boolean"}});var Er={};ha(Er,{Camera:()=>Sr,DEFAULT_CAMERA_STATE:()=>na,DEFAULT_DEPTH_LAYERS:()=>Ou,DEFAULT_EDGE_DEPTH_LAYERS:()=>Wu,DEFAULT_NODE_DEPTH_LAYERS:()=>Bu,DEFAULT_STYLES:()=>vt,DEPTHLESS_STYLES:()=>vi,MouseCaptor:()=>xo,SDFAtlasManager:()=>Ce,Sigma:()=>So,TouchCaptor:()=>yo,default:()=>Ve,easings:()=>Uu});function dn(n,a){(a==null||a>n.length)&&(a=n.length);for(var t=0,e=Array(a);t<a;t++)e[t]=n[t];return e}function fn(n,a){if(n){if(typeof n=="string")return dn(n,a);var t={}.toString.call(n).slice(8,-1);return t==="Object"&&n.constructor&&(t=n.constructor.name),t==="Map"||t==="Set"?Array.from(n):t==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)?dn(n,a):void 0}}function as(n){if(Array.isArray(n))return n}function rs(n,a){var t=n==null?null:typeof Symbol<"u"&&n[Symbol.iterator]||n["@@iterator"];if(t!=null){var e,r,i,o,s=[],l=!0,u=!1;try{if(i=(t=t.call(n)).next,a===0){if(Object(t)!==t)return;l=!1}else for(;!(l=(e=i.call(t)).done)&&(s.push(e.value),s.length!==a);l=!0);}catch(d){u=!0,r=d}finally{try{if(!l&&t.return!=null&&(o=t.return(),Object(o)!==o))return}finally{if(u)throw r}}return s}}function is(){throw new TypeError(`Invalid attempt to destructure non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function Z(n,a){return as(n)||rs(n,a)||fn(n,a)||is()}function G(n,a){var t=typeof Symbol<"u"&&n[Symbol.iterator]||n["@@iterator"];if(!t){if(Array.isArray(n)||(t=fn(n))||a&&n&&typeof n.length=="number"){t&&(n=t);var e=0,r=function(){};return{s:r,n:function(){return e>=n.length?{done:!0}:{done:!1,value:n[e++]}},e:function(l){throw l},f:r}}throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}var i,o=!0,s=!1;return{s:function(){t=t.call(n)},n:function(){var l=t.next();return o=l.done,l},e:function(l){s=!0,i=l},f:function(){try{o||t.return==null||t.return()}finally{if(s)throw i}}}}function re(){return Float32Array.of(1,0,0,0,1,0,0,0,1)}function ot(n,a,t){return n[0]=a,n[4]=typeof t=="number"?t:a,n}function cn(n,a){var t=Math.sin(a),e=Math.cos(a);return n[0]=e,n[1]=t,n[3]=-t,n[4]=e,n}function hn(n,a,t){return n[6]=a,n[7]=t,n}function pe(n,a){var t=n[0],e=n[1],r=n[2],i=n[3],o=n[4],s=n[5],l=n[6],u=n[7],d=n[8],c=a[0],p=a[1],v=a[2],f=a[3],b=a[4],g=a[5],h=a[6],m=a[7],x=a[8];return n[0]=c*t+p*i+v*l,n[1]=c*e+p*o+v*u,n[2]=c*r+p*s+v*d,n[3]=f*t+b*i+g*l,n[4]=f*e+b*o+g*u,n[5]=f*r+b*s+g*d,n[6]=h*t+m*i+x*l,n[7]=h*e+m*o+x*u,n[8]=h*r+m*s+x*d,n}function Pt(n,a){var t=Math.cos(a),e=Math.sin(a);return{x:t*n.x+e*n.y,y:-e*n.x+t*n.y}}function we(n,a){var t=arguments.length>2&&arguments[2]!==void 0?arguments[2]:1,e=n[0],r=n[1],i=n[3],o=n[4],s=n[6],l=n[7],u=a.x,d=a.y;return{x:u*e+d*i+s*t,y:u*r+d*o+l*t}}function fa(n,a){var t=n.height/n.width,e=a.height/a.width;return t<1&&e>1||t>1&&e<1?1:Math.min(Math.max(e,1/e),Math.max(1/t,t))}function be(n,a,t,e,r){var i=n.angle,o=n.ratio,s=n.x,l=n.y,u=a.width,d=a.height,c=re(),p=Math.min(u,d)-2*e,v=fa(a,t);return r?(pe(c,hn(re(),s,l)),pe(c,ot(re(),o)),pe(c,cn(re(),i)),pe(c,ot(re(),u/p/2/v,d/p/2/v))):(pe(c,ot(re(),2*(p/u)*v,2*(p/d)*v)),pe(c,cn(re(),-i)),pe(c,ot(re(),1/o)),pe(c,hn(re(),-s,-l))),c}function gn(n,a,t){var e=we(n,{x:Math.cos(a.angle),y:Math.sin(a.angle)},0),r=e.x,i=e.y;return 1/Math.sqrt(Math.pow(r,2)+Math.pow(i,2))/t.width}function Ft(n,a,t,e,r){var i=Math.floor(a/r*e),o=Math.floor(n.drawingBufferHeight/r-t/r*e);return[i,o]}var je={black:"#000000",silver:"#C0C0C0",gray:"#808080",grey:"#808080",white:"#FFFFFF",maroon:"#800000",red:"#FF0000",purple:"#800080",fuchsia:"#FF00FF",green:"#008000",lime:"#00FF00",olive:"#808000",yellow:"#FFFF00",navy:"#000080",blue:"#0000FF",teal:"#008080",aqua:"#00FFFF",darkblue:"#00008B",mediumblue:"#0000CD",darkgreen:"#006400",darkcyan:"#008B8B",deepskyblue:"#00BFFF",darkturquoise:"#00CED1",mediumspringgreen:"#00FA9A",springgreen:"#00FF7F",cyan:"#00FFFF",midnightblue:"#191970",dodgerblue:"#1E90FF",lightseagreen:"#20B2AA",forestgreen:"#228B22",seagreen:"#2E8B57",darkslategray:"#2F4F4F",darkslategrey:"#2F4F4F",limegreen:"#32CD32",mediumseagreen:"#3CB371",turquoise:"#40E0D0",royalblue:"#4169E1",steelblue:"#4682B4",darkslateblue:"#483D8B",mediumturquoise:"#48D1CC",indigo:"#4B0082",darkolivegreen:"#556B2F",cadetblue:"#5F9EA0",cornflowerblue:"#6495ED",rebeccapurple:"#663399",mediumaquamarine:"#66CDAA",dimgray:"#696969",dimgrey:"#696969",slateblue:"#6A5ACD",olivedrab:"#6B8E23",slategray:"#708090",slategrey:"#708090",lightslategray:"#778899",lightslategrey:"#778899",mediumslateblue:"#7B68EE",lawngreen:"#7CFC00",chartreuse:"#7FFF00",aquamarine:"#7FFFD4",skyblue:"#87CEEB",lightskyblue:"#87CEFA",blueviolet:"#8A2BE2",darkred:"#8B0000",darkmagenta:"#8B008B",saddlebrown:"#8B4513",darkseagreen:"#8FBC8F",lightgreen:"#90EE90",mediumpurple:"#9370DB",darkviolet:"#9400D3",palegreen:"#98FB98",darkorchid:"#9932CC",yellowgreen:"#9ACD32",sienna:"#A0522D",brown:"#A52A2A",darkgray:"#A9A9A9",darkgrey:"#A9A9A9",lightblue:"#ADD8E6",greenyellow:"#ADFF2F",paleturquoise:"#AFEEEE",lightsteelblue:"#B0C4DE",powderblue:"#B0E0E6",firebrick:"#B22222",darkgoldenrod:"#B8860B",mediumorchid:"#BA55D3",rosybrown:"#BC8F8F",darkkhaki:"#BDB76B",mediumvioletred:"#C71585",indianred:"#CD5C5C",peru:"#CD853F",chocolate:"#D2691E",tan:"#D2B48C",lightgray:"#D3D3D3",lightgrey:"#D3D3D3",thistle:"#D8BFD8",orchid:"#DA70D6",goldenrod:"#DAA520",palevioletred:"#DB7093",crimson:"#DC143C",gainsboro:"#DCDCDC",plum:"#DDA0DD",burlywood:"#DEB887",lightcyan:"#E0FFFF",lavender:"#E6E6FA",darksalmon:"#E9967A",violet:"#EE82EE",palegoldenrod:"#EEE8AA",lightcoral:"#F08080",khaki:"#F0E68C",aliceblue:"#F0F8FF",honeydew:"#F0FFF0",azure:"#F0FFFF",sandybrown:"#F4A460",wheat:"#F5DEB3",beige:"#F5F5DC",whitesmoke:"#F5F5F5",mintcream:"#F5FFFA",ghostwhite:"#F8F8FF",salmon:"#FA8072",antiquewhite:"#FAEBD7",linen:"#FAF0E6",lightgoldenrodyellow:"#FAFAD2",oldlace:"#FDF5E6",magenta:"#FF00FF",deeppink:"#FF1493",orangered:"#FF4500",tomato:"#FF6347",hotpink:"#FF69B4",coral:"#FF7F50",darkorange:"#FF8C00",lightsalmon:"#FFA07A",orange:"#FFA500",lightpink:"#FFB6C1",pink:"#FFC0CB",gold:"#FFD700",peachpuff:"#FFDAB9",navajowhite:"#FFDEAD",moccasin:"#FFE4B5",bisque:"#FFE4C4",mistyrose:"#FFE4E1",blanchedalmond:"#FFEBCD",papayawhip:"#FFEFD5",lavenderblush:"#FFF0F5",seashell:"#FFF5EE",cornsilk:"#FFF8DC",lemonchiffon:"#FFFACD",floralwhite:"#FFFAF0",snow:"#FFFAFA",lightyellow:"#FFFFE0",ivory:"#FFFFF0"},Or=new Int8Array(4),un=new Int32Array(Or.buffer,0,1),Br=new Float32Array(Or.buffer,0,1),os=/^\s*rgba?\s*\(/,ss=/^\s*rgba?\s*\(\s*([0-9]*)\s*,\s*([0-9]*)\s*,\s*([0-9]*)(?:\s*,\s*(.*)?)?\)\s*$/;function lt(n){var a=0,t=0,e=0,r=1,i=n.toLowerCase();if(i==="transparent")return{r:0,g:0,b:0,a:0};if(i in je)return lt(je[i]);if(n[0]==="#")n.length===4?(a=parseInt(n.charAt(1)+n.charAt(1),16),t=parseInt(n.charAt(2)+n.charAt(2),16),e=parseInt(n.charAt(3)+n.charAt(3),16)):(a=parseInt(n.charAt(1)+n.charAt(2),16),t=parseInt(n.charAt(3)+n.charAt(4),16),e=parseInt(n.charAt(5)+n.charAt(6),16)),n.length===9&&(r=parseInt(n.charAt(7)+n.charAt(8),16)/255);else if(os.test(n)){var o=n.match(ss);o&&(a=+o[1],t=+o[2],e=+o[3],o[4]&&(r=+o[4]))}return{r:a,g:t,b:e,a:r}}function ut(n){var a=arguments.length>1&&arguments[1]!==void 0?arguments[1]:!1,t=lt(n),e=t.r,r=t.g,i=t.b,o=t.a;return a?[e/255*o,r/255*o,i/255*o,o]:[e/255,r/255,i/255,o]}var st={};for(Lt in je)st[Lt]=ie(je[Lt]),st[je[Lt]]=st[Lt];var Lt;function ga(n,a,t,e,r){return un[0]=e<<24|t<<16|a<<8|n,r&&(un[0]=un[0]&4278190079),Br[0]}function ie(n){if(n=n.toLowerCase(),typeof st[n]<"u")return st[n];var a=lt(n),t=a.r,e=a.g,r=a.b,i=a.a;i=i*255|0;var o=ga(t,e,r,i,!0);return st[n]=o,o}function xe(n,a){Br[0]=ie(n);var t=un[0];a&&(t=t|16777216);var e=t&255,r=t>>8&255,i=t>>16&255,o=t>>24&255;return[e,r,i,o]}function Ie(n){var a=n>>>8&255,t=n>>>16&255,e=n>>>24&255,r=n&255;return(r<<24|e<<16|t<<8|a)>>>0}function wt(n,a,t,e){return(t<<24|a<<16|n<<8|e)>>>0}function vn(n,a,t,e,r,i){var o=Ft(n,t,e,r,i),s=Z(o,2),l=s[0],u=s[1],d=new Uint8Array(4);n.bindFramebuffer(n.FRAMEBUFFER,a),n.readPixels(l,u,1,1,n.RGBA,n.UNSIGNED_BYTE,d);var c=Z(d,4),p=c[0],v=c[1],f=c[2],b=c[3];return[p,v,f,b]}function mn(n){var a=lt(n),t=a.r,e=a.g,r=a.b,i=a.a,o=(t/255).toFixed(6),s=(e/255).toFixed(6),l=(r/255).toFixed(6),u=i.toFixed(6);return"vec4(".concat(o,", ").concat(s,", ").concat(l,", ").concat(u,")")}function ls(n,a){if(typeof n!="object"||!n)return n;var t=n[Symbol.toPrimitive];if(t!==void 0){var e=t.call(n,a||"default");if(typeof e!="object")return e;throw new TypeError("@@toPrimitive must return a primitive value.")}return(a==="string"?String:Number)(n)}function Hr(n){var a=ls(n,"string");return typeof a=="symbol"?a:a+""}function S(n,a,t){return(a=Hr(a))in n?Object.defineProperty(n,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):n[a]=t,n}function Wr(n,a){var t=Object.keys(n);if(Object.getOwnPropertySymbols){var e=Object.getOwnPropertySymbols(n);a&&(e=e.filter(function(r){return Object.getOwnPropertyDescriptor(n,r).enumerable})),t.push.apply(t,e)}return t}function O(n){for(var a=1;a<arguments.length;a++){var t=arguments[a]!=null?arguments[a]:{};a%2?Wr(Object(t),!0).forEach(function(e){S(n,e,t[e])}):Object.getOwnPropertyDescriptors?Object.defineProperties(n,Object.getOwnPropertyDescriptors(t)):Wr(Object(t)).forEach(function(e){Object.defineProperty(n,e,Object.getOwnPropertyDescriptor(t,e))})}return n}function X(n,a){if(!(n instanceof a))throw new TypeError("Cannot call a class as a function")}function Ur(n,a){for(var t=0;t<a.length;t++){var e=a[t];e.enumerable=e.enumerable||!1,e.configurable=!0,"value"in e&&(e.writable=!0),Object.defineProperty(n,Hr(e.key),e)}}function j(n,a,t){return a&&Ur(n.prototype,a),t&&Ur(n,t),Object.defineProperty(n,"prototype",{writable:!1}),n}function qe(n){return qe=Object.setPrototypeOf?Object.getPrototypeOf.bind():function(a){return a.__proto__||Object.getPrototypeOf(a)},qe(n)}function Vr(){try{var n=!Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],function(){}))}catch{}return(Vr=function(){return!!n})()}function us(n){if(n===void 0)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return n}function ds(n,a){if(a&&(typeof a=="object"||typeof a=="function"))return a;if(a!==void 0)throw new TypeError("Derived constructors may only return object or undefined");return us(n)}function Q(n,a,t){return a=qe(a),ds(n,Vr()?Reflect.construct(a,t||[],qe(n).constructor):a.apply(n,t))}function va(n,a){return va=Object.setPrototypeOf?Object.setPrototypeOf.bind():function(t,e){return t.__proto__=e,t},va(n,a)}function J(n,a){if(typeof a!="function"&&a!==null)throw new TypeError("Super expression must either be null or a function");n.prototype=Object.create(a&&a.prototype,{constructor:{value:n,writable:!0,configurable:!0}}),Object.defineProperty(n,"prototype",{writable:!1}),a&&va(n,a)}function cs(n){if(Array.isArray(n))return dn(n)}function hs(n){if(typeof Symbol<"u"&&n[Symbol.iterator]!=null||n["@@iterator"]!=null)return Array.from(n)}function fs(){throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function H(n){return cs(n)||hs(n)||fn(n)||fs()}function q(n){"@babel/helpers - typeof";return q=typeof Symbol=="function"&&typeof Symbol.iterator=="symbol"?function(a){return typeof a}:function(a){return a&&typeof Symbol=="function"&&a.constructor===Symbol&&a!==Symbol.prototype?"symbol":typeof a},q(n)}function oe(n){return q(n)==="object"&&n!==null&&"attribute"in n}function Ye(){var n=`
float sdf_circle(vec2 uv, float size) {
  return length(uv) - size;
}
`;return{name:"circle",glsl:n,uniforms:[]}}function dt(n){var a,t=WebGL2RenderingContext,e=t.UNSIGNED_BYTE,r=(a=n?.color)!==null&&a!==void 0?a:{attribute:"color"};if(!oe(r)){var i=r,o=`
vec4 layer_fill() {
  return `.concat(mn(i),`;
}
`);return{name:"fill",uniforms:[],attributes:[],glsl:o}}var s=r.attribute,l=`
vec4 layer_fill(vec4 v_fillColor) {
  return v_fillColor;
}
`;return{name:"fill",uniforms:[],attributes:[{name:"fillColor",size:4,type:e,normalized:!0,source:s}],glsl:l}}function Ke(n,a){if(typeof n=="string"){var t=ut(n).map(function(u){return u.toFixed(6)}),e=Z(t,4),r=e[0],i=e[1],o=e[2],s=e[3];return{glsl:"vec4(".concat(r,", ").concat(i,", ").concat(o,", ").concat(s,")"),attributes:[],needsNodeColors:!1}}if("node"in n&&n.node)return{glsl:n.node==="source"?"v_sourceColor":"v_targetColor",attributes:[],needsNodeColors:!0};var l=n;return{glsl:"v_".concat(a),attributes:[{name:"a_".concat(a),size:4,type:WebGL2RenderingContext.UNSIGNED_BYTE,normalized:!0,source:l.attribute,defaultValue:l.default}],needsNodeColors:!1}}function Ee(n){var a=n?.color;if(a===void 0){var t=`
// Plain solid color layer
vec4 layer_plain(EdgeContext ctx) {
  return v_color;
}
`;return{name:"plain",glsl:t,uniforms:[],attributes:[]}}var e=Ke(a,"plainColor"),r=`
// Plain solid color layer
vec4 layer_plain(EdgeContext ctx) {
  return `.concat(e.glsl,`;
}
`);return{name:"plain",glsl:r,uniforms:[],attributes:e.attributes,needsNodeColors:e.needsNodeColors}}function pn(){var n=`
// Position at parameter t \u2208 [0, 1]
vec2 path_straight_position(float t, vec2 source, vec2 target) {
  return mix(source, target, t);
}

// Total length of the path (analytical - more efficient than sampling)
float path_straight_length(vec2 source, vec2 target) {
  return length(target - source);
}
`;return{name:"straight",segments:1,minBodyLengthRatio:0,linearParameterization:!0,glsl:n,uniforms:[],attributes:[]}}function bn(n){var a=n??{},t=a.segments,e=t===void 0?32:t,r=`
const float LOOP_PI = 3.141592653589793;

float loopWorldRadius() {
  float nodeWorldRadius = v_sourceNodeSize * u_correctionRatio / u_sizeRatio;
  return max(v_loopRadius * nodeWorldRadius, 0.001);
}

// Cubic B\xE9zier with P0 = P3 = source.
// Control points extend outward orthogonal to the node surface at exit/entry angles.
vec2 path_loop_position(float t, vec2 source, vec2 target) {
  float R = loopWorldRadius();
  float angle = v_loopAngle + (v_loopFixedOrientation > 0.5 ? u_cameraAngle : 0.0);
  float halfSpread = v_loopSpread * 0.5;

  float exitAngle = angle - halfSpread;
  float entryAngle = angle + halfSpread;

  // Control point distance: at t=0.5 the B\xE9zier reaches 0.75 * cpDist * cos(halfSpread)
  // from source. Solve for cpDist so the loop tip reaches exactly R.
  float cpDist = R / (0.75 * cos(halfSpread));

  vec2 cp1 = source + cpDist * vec2(cos(exitAngle), sin(exitAngle));
  vec2 cp2 = source + cpDist * vec2(cos(entryAngle), sin(entryAngle));

  float u = 1.0 - t;
  vec2 d1 = cp1 - source;
  vec2 d2 = cp2 - source;
  return source + 3.0 * t * u * (u * d1 + t * d2);
}

// Approximate arc length via chord sampling
float path_loop_length(vec2 source, vec2 target) {
  float len = 0.0;
  vec2 prev = path_loop_position(0.0, source, target);
  const int STEPS = 16;
  for (int i = 1; i <= STEPS; i++) {
    float t = float(i) / float(STEPS);
    vec2 cur = path_loop_position(t, source, target);
    len += length(cur - prev);
    prev = cur;
  }
  return len;
}
`;return{name:"loop",segments:e,glsl:r,needsNodeSize:!0,uniforms:[],attributes:[{name:"loopRadius",size:1,type:WebGL2RenderingContext.FLOAT},{name:"loopAngle",size:1,type:WebGL2RenderingContext.FLOAT},{name:"loopSpread",size:1,type:WebGL2RenderingContext.FLOAT},{name:"loopFixedOrientation",size:1,type:WebGL2RenderingContext.FLOAT}],variables:{loopRadius:{type:"number",default:4},loopAngle:{type:"number",default:Math.PI/4},loopSpread:{type:"number",default:80*Math.PI/180},loopFixedOrientation:{type:"number",default:0}},spread:{variable:"loopRadius",compute:function(o){return o+4}}}}var oi=Se(Ze());function ti(n){return q(n)==="object"&&"glsl"in n&&!("attributes"in n)}function ni(n){return q(n)==="object"&&"glsl"in n&&!("attributes"in n)}var It={shapes:[Ye()],variables:{},layers:[dt()],label:{},backdrop:{},labelAttachments:{}},ht={paths:[pn(),bn()],extremities:[],variables:{},layers:[Ee()],defaultHead:"none",defaultTail:"none",label:{}},kt=["nodes","topNodes"],zt=["edges","topEdges"],Nt=[].concat(zt,kt),ai={nodes:It,edges:ht,depthLayers:H(Nt)};var pa=function(a){return a},ba=function(a){return a*a},xa=function(a){return a*(2-a)},ya=function(a){return(a*=2)<1?.5*a*a:-.5*(--a*(a-2)-1)},_a=function(a){return a*a*a},Ta=function(a){return--a*a*a+1},Sa=function(a){return(a*=2)<1?.5*a*a*a:.5*((a-=2)*a*a+2)},Ea=function(a){return a===0?0:Math.pow(2,10*(a-1))},Ra=function(a){return a===1?1:1-Math.pow(2,-10*a)},Aa=function(a){return a===0?0:a===1?1:a<.5?Math.pow(2,10*(2*a-1))/2:(2-Math.pow(2,-10*(2*a-1)))/2},ft={linear:pa,quadraticIn:ba,quadraticOut:xa,quadraticInOut:ya,cubicIn:_a,cubicOut:Ta,cubicInOut:Sa,exponentialIn:Ea,exponentialOut:Ra,exponentialInOut:Aa};function ke(n){return n?typeof n=="function"?n:ft[n]:ft.linear}function Ca(n){return q(n)==="object"&&n!==null&&"attribute"in n}function si(n){return typeof n=="function"}function li(n){return q(n)==="object"&&n!==null&&"when"in n&&typeof n.when=="function"&&"then"in n}function ui(n){return q(n)==="object"&&n!==null&&"whenState"in n&&"then"in n}function di(n){return q(n)==="object"&&n!==null&&"whenData"in n&&"then"in n}var ys={isHovered:!1,isLabelHovered:!1,isHidden:!1,isHighlighted:!1,isDragged:!1},_s={isHovered:!1,isLabelHovered:!1,isHidden:!1,isHighlighted:!1,parallelIndex:0,parallelCount:1},Ts={isIdle:!0,isPanning:!1,isZooming:!1,isDragging:!1,hasHovered:!1,hasHighlighted:!1};function ci(n){return O(O({},ys),n)}function hi(n){return O(O({},_s),n)}function La(n){return O(O({},Ts),n)}var fi={x:{attribute:"x"},y:{attribute:"y"},size:{whenState:"isHovered",then:{attribute:"size",defaultValue:12},else:{attribute:"size",defaultValue:10}},color:{attribute:"color",defaultValue:"#666"},label:{attribute:"label"},visibility:{whenState:"isHidden",then:"hidden",else:"visible"},labelVisibility:{whenState:"isHovered",then:"visible",else:"auto"},backdropVisibility:{whenState:"isHovered",then:"visible",else:"hidden"},backdropColor:"#ffffff",backdropShadowColor:"rgba(0, 0, 0, 0.5)",backdropShadowBlur:12,backdropPadding:6},gi={size:{attribute:"size",defaultValue:1},color:{attribute:"color",defaultValue:"#ccc"},label:{attribute:"label"},visibility:{whenState:"isHidden",then:"hidden",else:"visible"}},vi={nodes:fi,edges:gi},vt={nodes:O(O({},fi),{},{depth:{whenState:"isHovered",then:"topNodes",else:"nodes"}}),edges:O(O({},gi),{},{depth:{whenState:["isHighlighted","isHovered"],then:"topEdges",else:"edges"}})};function Ss(n){return"min"in n||"max"in n||"minValue"in n||"maxValue"in n||"easing"in n}function Es(n){return"dict"in n}function Tn(n,a){return typeof n=="string"?a[n]===!0:Array.isArray(n)?n.every(function(t){return a[t]===!0}):q(n)==="object"&&n!==null?Object.entries(n).every(function(t){var e=Z(t,2),r=e[0],i=e[1];return a[r]===i}):!1}function Rs(n,a){var t=a[n.attribute];return t===void 0?n.defaultValue:t}function As(n,a,t){var e,r,i,o,s=a[n.attribute];if(s===void 0)return n.defaultValue;var l=Number(s);if(isNaN(l))return n.defaultValue;if(n.min===void 0&&n.max===void 0)return l;var u=(e=n.minValue)!==null&&e!==void 0?e:l,d=(r=n.maxValue)!==null&&r!==void 0?r:l;if(d===u){var c;return(c=n.min)!==null&&c!==void 0?c:l}var p=(l-u)/(d-u);p=Math.max(0,Math.min(1,p));var v=ke(n.easing);p=v(p);var f=(i=n.min)!==null&&i!==void 0?i:0,b=(o=n.max)!==null&&o!==void 0?o:1;return f+p*(b-f)}function Ds(n,a){var t=a[n.attribute];if(t===void 0)return n.defaultValue;var e=String(t);return e in n.dict?n.dict[e]:n.defaultValue}function Cs(n,a,t){return Es(n)?Ds(n,a):Ss(n)?As(n,a):Rs(n,a)}function mi(n,a){return typeof n=="string"?!!a[n]:Array.isArray(n)?n.every(function(t){return!!a[t]}):q(n)==="object"&&n!==null?Object.entries(n).every(function(t){var e=Z(t,2),r=e[0],i=e[1];return a[r]===i}):!1}function _n(n,a,t,e,r,i){if(n==null)return i;if(q(n)!=="object"&&typeof n!="function")return n;if(li(n)){var o=n.when(a,t,e,r)?n.then:n.else;return o===void 0?i:_n(o,a,t,e,r,i)}if(ui(n)){var s=Tn(n.whenState,t)?n.then:n.else;return s===void 0?i:_n(s,a,t,e,r,i)}if(di(n)){var l=mi(n.whenData,a)?n.then:n.else;return l===void 0?i:_n(l,a,t,e,r,i)}if(si(n)){var u=n(a,t,e,r);return u??i}if(Ca(n)){var d=Cs(n,a);return d??i}return n}function ve(n){if(n==null)return"static";if(li(n))return"graph-state";if(ui(n)){var a=ve(n.then),t=n.else!==void 0?ve(n.else):"static";return he("item-state",he(a,t))}if(di(n)){var e=ve(n.then),r=n.else!==void 0?ve(n.else):"static";return he(e,r)}return si(n)?"graph-state":(Ca(n),"static")}function he(n,a){return n==="graph-state"||a==="graph-state"?"graph-state":n==="item-state"||a==="item-state"?"item-state":"static"}function Pa(n){if(!n)return{dependency:"static",xAttribute:null,yAttribute:null};var a=Array.isArray(n)?n:[n],t="static",e=null,r=null,i=G(a),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;if("matchData"in s&&"cases"in s)for(var l=s.cases,u=0,d=Object.values(l);u<d.length;u++)for(var c=d[u],p=0,v=Object.values(c);p<v.length;p++){var f=v[p];t=he(t,ve(f))}else if("matchState"in s&&"cases"in s){t=he(t,"item-state");for(var b=s.cases,g=0,h=Object.values(b);g<h.length;g++)for(var m=h[g],x=0,y=Object.values(m);x<y.length;x++){var _=y[x];t=he(t,ve(_))}}else if("when"in s&&"then"in s)t="graph-state";else if("whenState"in s){t=he(t,"item-state");var T=s.then;if(T&&q(T)==="object")for(var R=0,E=Object.values(T);R<E.length;R++){var D=E[R];t=he(t,ve(D))}var P=s.else;if(P&&q(P)==="object")for(var w=0,A=Object.values(P);w<A.length;w++){var F=A[w];t=he(t,ve(F))}}else if("whenData"in s){var L=s.then;if(L&&q(L)==="object")for(var k=0,N=Object.values(L);k<N.length;k++){var z=N[k];t=he(t,ve(z))}var I=s.else;if(I&&q(I)==="object")for(var C=0,M=Object.values(I);C<M.length;C++){var W=M[C];t=he(t,ve(W))}}else for(var B=0,U=Object.entries(s);B<U.length;B++){var V=Z(U[B],2),K=V[0],ee=V[1];if(!wa.has(K)&&(t=he(t,ve(ee)),(K==="x"||K==="y")&&Ca(ee))){var ce=ee.attribute;K==="x"&&!e&&(e=ce),K==="y"&&!r&&(r=ce)}}}}catch(ge){i.e(ge)}finally{i.f()}return{dependency:t,xAttribute:e,yAttribute:r}}var Re={size:10,color:"#666",opacity:1,shape:"circle",rotationAlignment:"viewport",labelRotationAlignment:"viewport",visibility:"visible",depth:"nodes",zIndex:0,label:"",labelColor:"#000",labelSize:12,labelFont:"sans-serif",labelVisibility:"auto",labelPosition:"right",labelAngle:0,labelDepth:"nodes",backdropVisibility:"hidden",backdropColor:"transparent",backdropShadowColor:"transparent",backdropShadowBlur:0,backdropPadding:0,backdropBorderColor:"transparent",backdropBorderWidth:0,backdropCornerRadius:0,backdropLabelPadding:-1,backdropArea:"both",labelAttachment:null,labelAttachmentPlacement:"below"},Fa={size:1,color:"#ccc",opacity:1,path:"straight",selfLoopPath:"loop",parallelSpread:.25,tail:"none",head:"none",visibility:"visible",depth:"edges",zIndex:0,label:"",labelColor:"#666",labelVisibility:"auto",labelDepth:"edges"},wa=new Set(["when","whenState","whenData","then","else"]),ri=Object.keys(Re),Ls=Object.values(Re),ii=Object.keys(Fa),Ps=Object.values(Fa);function gt(n,a,t,e,r,i,o){for(var s in a){var l;if(!wa.has(s)){var u=(l=n[s])!==null&&l!==void 0?l:o[s];n[s]=_n(a[s],t,e,r,i,u)}}"depth"in a&&!("labelDepth"in a)&&(n.labelDepth=n.depth)}function pi(n,a,t,e,r,i,o){var s=G(a),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;if("matchData"in u&&"cases"in u){var d,c=String((d=t[u.matchData])!==null&&d!==void 0?d:""),p=u.cases;c in p&&gt(n,p[c],t,e,r,i,o)}else if("matchState"in u&&"cases"in u){var v,f=String((v=e[u.matchState])!==null&&v!==void 0?v:""),b=u.cases;f in b&&gt(n,b[f],t,e,r,i,o)}else if("when"in u&&"then"in u){var g=u.when;if(!g(t,e,r,i))continue;gt(n,u.then,t,e,r,i,o)}else if("whenState"in u&&"then"in u){if(!Tn(u.whenState,e))continue;gt(n,u.then,t,e,r,i,o)}else if("whenData"in u&&"then"in u){if(!mi(u.whenData,t))continue;gt(n,u.then,t,e,r,i,o)}else gt(n,u,t,e,r,i,o)}}catch(h){s.e(h)}finally{s.f()}}function Ia(n,a,t,e,r,i){for(var o=i||{},s=o,l=0,u=ri.length;l<u;l++)s[ri[l]]=Ls[l];if(s.x=void 0,s.y=void 0,s.labelBackgroundColor=void 0,s.labelBackgroundPadding=void 0,s.labelCursor=void 0,!n){var d,c,p,v,f;return s.x=(d=a.x)!==null&&d!==void 0?d:0,s.y=(c=a.y)!==null&&c!==void 0?c:0,o.size=(p=a.size)!==null&&p!==void 0?p:10,o.color=(v=a.color)!==null&&v!==void 0?v:"#666",o.label=(f=a.label)!==null&&f!==void 0?f:"",o}var b=Array.isArray(n)?n:[n];return pi(s,b,a,t,e,r,Re),o}function ka(n,a,t,e,r,i){for(var o=i||{},s=o,l=0,u=ii.length;l<u;l++)s[ii[l]]=Ps[l];if(!n){var d,c,p;return o.size=(d=a.size)!==null&&d!==void 0?d:1,o.color=(c=a.color)!==null&&c!==void 0?c:"#ccc",o.label=(p=a.label)!==null&&p!==void 0?p:"",o}var v=Array.isArray(n)?n:[n];return pi(s,v,a,t,e,r,Fa),typeof s.labelPosition=="number"&&(s.labelPosition=void 0),o}function Fs(n,a,t){var e,r;if(n==null)return t;if(typeof n=="function")return(e=n(a))!==null&&e!==void 0?e:t;if(q(n)==="object"&&"when"in n){var i,o=n,s=o.when(a),l=s?o.then:o.else;return l===void 0?t:typeof l=="function"?(i=l(a))!==null&&i!==void 0?i:t:l??t}if(q(n)==="object"&&"whenState"in n){var u,d=n,c=Tn(d.whenState,a),p=c?d.then:d.else;return p===void 0?t:typeof p=="function"?(u=p(a))!==null&&u!==void 0?u:t:p??t}return(r=n)!==null&&r!==void 0?r:t}function za(n,a){var t={};if(!n)return t;var e=Array.isArray(n)?n:[n],r=G(e),i;try{for(r.s();!(i=r.n()).done;){var o=i.value;if("when"in o&&"then"in o){var s=o.when(a),l=s?o.then:o.else;l&&q(l)==="object"&&Da(t,l,a)}else if("whenState"in o&&"then"in o){var u=Tn(o.whenState,a),d=u?o.then:o.else;d&&q(d)==="object"&&Da(t,d,a)}else Da(t,o,a)}}catch(c){r.e(c)}finally{r.f()}return t}function Da(n,a,t){for(var e=0,r=Object.entries(a);e<r.length;e++){var i=Z(r[e],2),o=i[0],s=i[1];wa.has(o)||(n[o]=Fs(s,t))}}var Sn=(function(n){function a(){var t;return X(this,a),t=Q(this,a),t.rawEmitter=t,t}return J(a,n),j(a)})(oi.EventEmitter);var bi=ai;function Mt(n,a){var t=a.size;if(t!==0){var e=n.length;n.length+=t;var r=0;a.forEach(function(i){n[e+r]=i,r++})}}function En(n){n=n||{};for(var a=0,t=arguments.length<=1?0:arguments.length-1;a<t;a++){var e=a+1<1||arguments.length<=a+1?void 0:arguments[a+1];e&&Object.assign(n,e)}return n}function ze(n,a){for(var t in a)if(Object.prototype.hasOwnProperty.call(a,t)&&a[t]!==n[t])return!0;return!1}function Rn(n,a){var t=n,e=a;for(var r in t)if(Object.prototype.hasOwnProperty.call(t,r)&&t[r]!==e[r])return!1;for(var i in e)if(Object.prototype.hasOwnProperty.call(e,i)&&e[i]!==t[i])return!1;return!0}function Ae(n,a,t){t?n.add(a):n.delete(a)}var yi=Se(An());var Gt={easing:"quadraticInOut",duration:150};function _i(n,a,t,e){var r=Object.assign({},Gt,t),i=ke(r.easing),o=Date.now(),s={};for(var l in a){var u=a[l];s[l]={};for(var d in u)s[l][d]=n.getNodeAttribute(l,d)}var c=null,p=function(){c=null;var f=(Date.now()-o)/r.duration;if(f>=1){for(var b in a){var g=a[b];for(var h in g)n.setNodeAttribute(b,h,g[h])}typeof e=="function"&&e();return}f=i(f);for(var m in a){var x=a[m],y=s[m];for(var _ in x)n.setNodeAttribute(m,_,x[_]*f+y[_]*(1-f))}c=requestAnimationFrame(p)};return p(),function(){c&&cancelAnimationFrame(c)}}function ye(n){return n.labelVisibility==="visible"&&n.visibility!=="hidden"}function Ot(n){return n.backdropVisibility==="visible"&&n.visibility!=="hidden"}function mt(n){return[n.rotationAlignment==="graph"?1:0,n.labelRotationAlignment==="graph"?1:0]}function Bt(n,a,t){var e=n[a];if(e)for(var r=0;r<e.length;r++){var i=e[r];if(!(t<i.offset||t>=i.offset+i.count)){if(i.count===1)e.splice(r,1);else if(t===i.offset)i.offset++,i.count--;else if(t===i.offset+i.count-1)i.count--;else{var o=t+1,s=i.offset+i.count-o;i.count=t-i.offset,e.splice(r+1,0,{offset:o,count:s})}return}}}function Wt(n,a,t){if(!n[a]){n[a]=[{offset:t,count:1}];return}for(var e=n[a],r=e.length,i=0;i<e.length;i++)if(t<e[i].offset){r=i;break}var o=r>0?e[r-1]:null,s=r<e.length?e[r]:null,l=o&&o.offset+o.count===t,u=s&&t+1===s.offset;l&&u?(o.count+=1+s.count,e.splice(r,1)):l?o.count++:u?(s.offset--,s.count++):e.splice(r,0,{offset:t,count:1})}function Dn(n){if(!(0,yi.default)(n))throw new Error("Sigma: invalid graph instance.")}function pt(n){var a=Z(n.x,2),t=a[0],e=a[1],r=Z(n.y,2),i=r[0],o=r[1],s=Math.max(e-t,o-i),l=(e+t)/2,u=(o+i)/2;(s===0||Math.abs(s)===1/0||isNaN(s))&&(s=1),isNaN(l)&&(l=0),isNaN(u)&&(u=0);var d=function(p){return{x:.5+(p.x-l)/s,y:.5+(p.y-u)/s}};return d.applyTo=function(c){c.x=.5+(c.x-l)/s,c.y=.5+(c.y-u)/s},d.inverse=function(c){return{x:l+s*(c.x-.5),y:u+s*(c.y-.5)}},d.ratio=s,d}var Cn={hideEdgesOnMove:!1,hideLabelsOnMove:!1,renderLabels:!0,renderEdgeLabels:!1,edgeLabelAnchors:"nodeLabels",enableEdgeEvents:!1,nodeLabelEvents:!1,edgeLabelEvents:!1,pickingDownSizingRatio:2,nodePickingPadding:0,edgePickingPadding:4,labelPickingPadding:10,stagePadding:30,minEdgeThickness:1.7,antiAliasingFeather:1,antialiasEdges:!0,antialiasNodes:!0,dragTimeout:100,draggedEventsTolerance:3,inertiaDuration:200,inertiaRatio:3,zoomDuration:250,zoomingRatio:1.7,doubleClickTimeout:300,doubleClickZoomingRatio:2.2,doubleClickZoomingDuration:200,tapMoveTolerance:10,zoomToSizeRatioFunction:Math.sqrt,itemSizesReference:"positions",autoRescale:!0,autoRescaleContent:"positions",enableNodeDrag:!1,getDraggedNodes:function(a){return[a]},dragPositionToAttributes:null,labelDensity:1,labelGridCellSize:100,labelRenderedSizeThreshold:6,labelPixelSnapping:!0,minCameraRatio:null,maxCameraRatio:null,enableCameraZooming:!0,enableCameraPanning:!0,enableCameraRotation:!0,enableCameraMouseRotation:!0,cameraPanBoundaries:null,gestureTarget:"graph",sharedGestureWheelMessage:"Use Ctrl + scroll to zoom the graph",sharedGestureAppleWheelMessage:"Use \u2318 + scroll to zoom the graph",sharedGestureTouchMessage:"Use two fingers to move the graph",allowInvalidContainer:!1,DEBUG_displayPickingLayer:!1,DEBUG_logShaders:!1,DEBUG_logRenderStats:!1,DEBUG_gpuTimerQueries:!1};function Ln(n){if(typeof n.labelDensity!="number"||n.labelDensity<0)throw new Error("Settings: invalid `labelDensity`. Expecting a positive number.");var a=n.minCameraRatio,t=n.maxCameraRatio;if(typeof a=="number"&&typeof t=="number"&&t<a)throw new Error("Settings: invalid camera ratio boundaries. Expecting `maxCameraRatio` to be greater than `minCameraRatio`.")}function Ti(n){return En({},Cn,n)}var ws=new Set(["italic","oblique"]),Is=new Set(["bold","bolder","lighter"]);function bt(n){for(var a="normal",t="normal",e=n.trim(),r=e.split(/\s+/),i=0,o=0;o<r.length;o++){var s=r[o].toLowerCase();if(ws.has(s))t=s,i=o+1;else if(Is.has(s)||/^\d{3}$/.test(s))a=s,i=o+1;else if(s==="normal")i=o+1;else break}var l=r.slice(i).join(" ");return{family:l||e,weight:a,style:t}}function Ne(n,a,t){var e=document.createElement(n);if(a)for(var r in a)e.style[r]=a[r];if(t)for(var i in t)e.setAttribute(i,t[i]);return e}function $e(){return typeof window.devicePixelRatio<"u"?window.devicePixelRatio:1}var Li=Se(Ze());function ks(n){var a=n.type===WebGL2RenderingContext.FLOAT&&!n.normalized,t=n.type===WebGL2RenderingContext.UNSIGNED_BYTE&&n.size===4&&n.normalized;if(!a&&!t)throw new Error('Attribute "'.concat(n.name,'" is invalid: only non-normalized FLOAT and normalized UNSIGNED_BYTE with size 4 are supported.'));return n.normalized?1:n.size}function Vt(n){var a=0;return n.forEach(function(t){return a+=ks(t)}),a}function Pi(n,a,t){var e=n==="VERTEX"?a.VERTEX_SHADER:a.FRAGMENT_SHADER,r=a.createShader(e);if(r===null)throw new Error("loadShader: error while creating the shader");a.shaderSource(r,t),a.compileShader(r);var i=a.getShaderParameter(r,a.COMPILE_STATUS);if(!i){var o=a.getShaderInfoLog(r);throw a.deleteShader(r),new Error(`loadShader: error while compiling the shader:
`.concat(o,`
`).concat(t))}return r}function qt(n,a){return Pi("VERTEX",n,a)}function Yt(n,a){return Pi("FRAGMENT",n,a)}function Kt(n,a){var t=n.createProgram();if(t===null)throw new Error("loadProgram: error while creating the program.");var e,r;for(e=0,r=a.length;e<r;e++)n.attachShader(t,a[e]);n.linkProgram(t);var i=n.getProgramParameter(t,n.LINK_STATUS);if(!i){var o=n.getProgramInfoLog(t);throw n.deleteProgram(t),new Error("loadProgram: error while linking the program: ".concat(o))}return t}function zn(n){var a=n.gl,t=n.buffer,e=n.program,r=n.vertexShader,i=n.fragmentShader;a.deleteShader(r),a.deleteShader(i),a.deleteProgram(e),a.deleteBuffer(t)}function Y(n){return n%1===0?n.toFixed(1):n.toString()}var De=new Map,Ma=new Map,Fi=0;function Gn(n,a){var t,e=(t=n.variables)===null||t===void 0||(t=t[a.source||a.name.replace(/^a_/,"")])===null||t===void 0?void 0:t.default,r=typeof e=="number"?e:typeof a.defaultValue=="number"?a.defaultValue:0;return Y(r)}function yt(n,a,t){var e,r=arguments.length>3&&arguments[3]!==void 0?arguments[3]:function(o){return"v_".concat(o.name.replace(/^a_/,""))},i=[a,t].concat(H(n.uniforms.filter(function(o){return o.type==="float"}).map(function(o){var s;return Y((s=o.value)!==null&&s!==void 0?s:0)})),H(((e=n.attributes)!==null&&e!==void 0?e:[]).map(r)));return"sdf_".concat(n.name,"(").concat(i.join(", "),")")}function zs(n){var a,t=n.name,e=n.uniforms.filter(function(o){return o.type==="float"&&o.value!==void 0&&o.value!==0}).map(function(o){return"".concat(o.name.replace("u_",""),"=").concat(o.value)}).sort(),r=((a=n.attributes)!==null&&a!==void 0?a:[]).map(function(o){var s;return"".concat(o.name,"@").concat((s=o.source)!==null&&s!==void 0?s:"","=").concat(Gn(n,o))}),i=[].concat(H(e),H(r));return i.length>0&&(t+="#"+i.join("#")),t}function Ga(n){var a=zs(n);if(!De.has(a)){var t={},e=G(n.uniforms),r;try{for(e.s();!(r=e.n()).done;){var i=r.value;i.type==="float"&&i.value!==void 0&&(t[i.name]=i.value)}}catch(o){e.e(o)}finally{e.f()}De.set(a,{shape:n,uniformValues:t,slug:a}),Ma.set(a,Fi++)}return a}function wi(n){return De.get(n)}function Ii(n){var a;return(a=De.get(n))===null||a===void 0?void 0:a.shape}function Qe(n){var a;return(a=Ma.get(n))!==null&&a!==void 0?a:-1}function ki(){return Array.from(De.keys())}function zi(n){var a,t;return(a=(t=De.get(n))===null||t===void 0?void 0:t.shape.glsl)!==null&&a!==void 0?a:""}function Ni(n){var a=[],t=new Set,e=new Set,r=/mat2 rotate2D\(float angle\)\s*\{[^}]+\}/,i=G(n),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;if(!e.has(s.name)){e.add(s.name);var l=s.glsl;r.test(l)&&(t.has("rotate2D")?l=l.replace(r,""):t.add("rotate2D")),a.push(l)}}}catch(u){i.e(u)}finally{i.f()}return a.join(`
`)}function Oa(){return Ni(Array.from(De.values()).map(function(n){return n.shape}))}function Ba(n){var a=Array.from(De.entries());if(a.length===0)return`
float querySDF(int shapeId, vec2 uv, float size) {
  return length(uv) - size;
}
`;var t=a.map(function(e,r){var i=Z(e,2),o=i[0],s=i[1].shape,l=yt(s,"uv","size",function(u){var d=u.name.replace(/^a_/,"");return n!=null&&n.has(d)?"g_".concat(d):Gn(s,u)});return"    case ".concat(r,": return ").concat(l,"; // ").concat(o)}).join(`
`);return`
float querySDF(int shapeId, vec2 uv, float size) {
  switch (shapeId) {
`.concat(t,`
    default: return length(uv) - size;
  }
}
`)}function Zt(n){return Ni(n)}function Je(n){return H(new Map(n.flatMap(function(a){return a.uniforms}).map(function(a){return[a.name,a]})).values())}function Wa(n,a){if(n.length===0)return`
void queryNodeSDF(int shapeId, vec2 uv, float size) {
  context.sdf = length(uv) - size;
  context.inradiusFactor = 1.0;
}
`;var t=function(c){return yt(c,"uv","size")},e=function(c){var p,v;return(p=c.inradiusFactorGLSL)!==null&&p!==void 0?p:Y((v=c.inradiusFactor)!==null&&v!==void 0?v:1)};if(n.length===1){var r=n[0];return`
void queryNodeSDF(int shapeId, vec2 uv, float size) {
  context.sdf = `.concat(t(r),`;
  context.inradiusFactor = `).concat(e(r),`;
}
`)}var i=n.map(function(d,c){return"    case ".concat(c,": // ").concat(d.name,`
      context.sdf = `).concat(t(d),`;
      context.inradiusFactor = `).concat(e(d),`;
      break;`)}).join(`
`),o=n[0],s="",l="shapeId";if(a&&a.length>1){var u=a.map(function(d,c){return"    case ".concat(d,": return ").concat(c,"; // ").concat(n[c].name)}).join(`
`);s=`
int globalToLocalShapeId(int globalId) {
  switch (globalId) {
`.concat(u,`
    default: return 0;
  }
}
`),l="globalToLocalShapeId(shapeId)"}return"".concat(s,`
void queryNodeSDF(int shapeId, vec2 uv, float size) {
  switch (`).concat(l,`) {
`).concat(i,`
    default:
      context.sdf = `).concat(t(o),`;
      context.inradiusFactor = `).concat(e(o),`;
  }
}
`)}function Mi(){De.clear(),Ma.clear(),Fi=0}var Oe={right:0,left:1,above:2,below:3,over:4},Be=5,$t=3,On=`
float matrixScaleX = length(vec2(u_matrix[0][0], u_matrix[1][0]));
float nodeRadiusGraphSpace = nodeSize * u_correctionRatio / u_sizeRatio * 2.0;
float nodeRadiusNDC = nodeRadiusGraphSpace * matrixScaleX;
float nodeRadiusPixels = nodeRadiusNDC * u_resolution.x / 2.0;
`,We=`
mat2 rotate2D(float angle) {
  float c = cos(angle);
  float s = sin(angle);
  return mat2(c, -s, s, c);
}
`,Bn=`
vec2 getLabelDirection(float positionMode) {
  if (positionMode < 0.5) return vec2(1.0, 0.0);   // Right
  if (positionMode < 1.5) return vec2(-1.0, 0.0);  // Left
  if (positionMode < 2.5) return vec2(0.0, -1.0);  // Above
  if (positionMode < 3.5) return vec2(0.0, 1.0);   // Below
  return vec2(0.0);                                 // Over (centered)
}
`,Ua=`
float sdfBox(vec2 p, vec2 halfSize) {
  vec2 d = abs(p) - halfSize;
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0);
}
`,Ha=`
float sdfRotatedBox(vec2 p, vec2 halfSize, float angle) {
  float c = cos(-angle);
  float s = sin(-angle);
  vec2 rotatedP = mat2(c, -s, s, c) * p;
  return sdfBox(rotatedP, halfSize);
}
`,Va=`
float sdfRoundedBox(vec2 p, vec2 halfSize, float radius) {
  vec2 d = abs(p) - halfSize + radius;
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0) - radius;
}
`,Xa=`
float sdfRoundedRotatedBox(vec2 p, vec2 halfSize, float angle, float radius) {
  float c = cos(-angle);
  float s = sin(-angle);
  vec2 rotatedP = mat2(c, -s, s, c) * p;
  return sdfRoundedBox(rotatedP, halfSize, radius);
}
`,Wn=`
vec2 labelBoxCenter(float positionMode, float labelStart, vec2 halfSize, float textHalfY) {
  if (positionMode < 0.5) return vec2(labelStart + halfSize.x, 0.0);    // right
  if (positionMode < 1.5) return vec2(-(labelStart + halfSize.x), 0.0); // left
  if (positionMode < 2.5) return vec2(0.0, -(labelStart + textHalfY));  // above
  if (positionMode < 3.5) return vec2(0.0, labelStart + textHalfY);     // below
  return vec2(0.0);                                                     // over
}
`,Qt=2,me=`
vec4 readNodeData(sampler2D nodeDataTexture, int nodeDataTextureWidth, int nodeIndex) {
  int t = nodeIndex * `.concat(Qt,`;
  ivec2 coord = ivec2(t % nodeDataTextureWidth, t / nodeDataTextureWidth);
  return texelFetch(nodeDataTexture, coord, 0);
}
`),Le=`
vec4 readNodeFlags(sampler2D nodeDataTexture, int nodeDataTextureWidth, int nodeIndex) {
  int t = nodeIndex * `.concat(Qt,` + 1;
  ivec2 coord = ivec2(t % nodeDataTextureWidth, t / nodeDataTextureWidth);
  return texelFetch(nodeDataTexture, coord, 0);
}
`),ja=`
vec4 readNodeColor(sampler2D nodeDataTexture, int nodeDataTextureWidth, int nodeIndex) {
  int t = nodeIndex * `.concat(Qt,` + 1;
  ivec2 coord = ivec2(t % nodeDataTextureWidth, t / nodeDataTextureWidth);
  vec4 texel = texelFetch(nodeDataTexture, coord, 0);
  float r = floor(texel.b / 65536.0);
  float g = floor(mod(texel.b, 65536.0) / 256.0);
  float b = mod(texel.b, 256.0);
  return vec4(r / 255.0, g / 255.0, b / 255.0, texel.a);
}
`),Ue=`
vec4 readFrameTexel(sampler2D frameTexture, int frameTextureWidth, int index) {
  ivec2 coord = ivec2(index % frameTextureWidth, index / frameTextureWidth);
  return texelFetch(frameTexture, coord, 0);
}
`;function qa(n,a){var t=function(o){return yt(o,"uv","size")};if(n.length===1)return{code:Si(t(n[0])),multiShape:!1};var e=n.map(function(i,o){return"    case ".concat(a?a[o]:o,": return ").concat(t(i),";")}).join(`
`),r=`
float queryShapeSDF(int shapeId, vec2 uv, float size) {
  switch (shapeId) {
`.concat(e,`
    default: return `).concat(t(n[0]),`;
  }
}
int g_shapeId;
`).concat(Si("queryShapeSDF(g_shapeId, uv, size)"),`
`);return{code:r,multiShape:!0}}function Si(n){return`
float findEdgeDistance(vec2 direction, float size) {
  float lo = 0.0, hi = 2.0;
  for (int i = 0; i < 8; i++) {
    float mid = (lo + hi) * 0.5;
    vec2 uv = direction * mid;
    if (`.concat(n,` < 0.0) lo = mid; else hi = mid;
  }
  return (lo + hi) * 0.5;
}
`)}function Ns(n,a){for(;!{}.hasOwnProperty.call(n,a)&&(n=qe(n))!==null;);return n}function Na(){return Na=typeof Reflect<"u"&&Reflect.get?Reflect.get.bind():function(n,a,t){var e=Ns(n,a);if(e){var r=Object.getOwnPropertyDescriptor(e,a);return r.get?r.get.call(arguments.length<3?n:t):r.value}},Na.apply(null,arguments)}function te(n,a,t,e){var r=Na(qe(1&e?n.prototype:n),a,t);return 2&e&&typeof r=="function"?function(i){return r.apply(t,i)}:r}var Ms=1024,Gs=1.5,Os=4096,Gi=-1,_t=(function(){function n(a,t){var e=arguments.length>2&&arguments[2]!==void 0?arguments[2]:Ms;X(this,n),S(this,"texture",null),S(this,"dirty",!1),S(this,"dirtyRangeStart",1/0),S(this,"dirtyRangeEnd",-1),S(this,"indexMap",new Map),S(this,"freeIndices",[]),S(this,"nextIndex",0),this.gl=a,this.TEXELS_PER_ITEM=t,this.capacity=this.roundUpToPowerOfTwo(e);var r=this.computeTextureDimensions(this.capacity);this.textureWidth=r.width,this.textureHeight=r.height,this.data=new Float32Array(this.textureWidth*this.textureHeight*4),this.createTexture()}return j(n,[{key:"computeTextureDimensions",value:function(t){var e=t*this.TEXELS_PER_ITEM,r=Math.min(e,Os),i=Math.ceil(e/r);return{width:r,height:i}}},{key:"roundUpToPowerOfTwo",value:function(t){return Math.pow(2,Math.ceil(Math.log2(Math.max(1,t))))}},{key:"createTexture",value:function(){var t=this.gl;this.texture=t.createTexture(),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,this.texture),t.texImage2D(t.TEXTURE_2D,0,t.RGBA32F,this.textureWidth,this.textureHeight,0,t.RGBA,t.FLOAT,this.data),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,t.NEAREST),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,t.NEAREST),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),t.bindTexture(t.TEXTURE_2D,null)}},{key:"resize",value:function(t){if(!(t<=this.capacity)){var e=this.roundUpToPowerOfTwo(Math.ceil(t*Gs)),r=this.gl,i=this.computeTextureDimensions(e),o=new Float32Array(i.width*i.height*4);o.set(this.data),this.texture&&r.deleteTexture(this.texture),this.data=o,this.capacity=e,this.textureWidth=i.width,this.textureHeight=i.height,this.createTexture(),this.dirty=!0,this.dirtyRangeStart=0,this.dirtyRangeEnd=this.nextIndex}}},{key:"allocate",value:function(t){var e=this.indexMap.get(t);if(e!==void 0)return e;var r;return this.freeIndices.length>0?r=this.freeIndices.pop():(r=this.nextIndex++,r>=this.capacity&&this.resize(r+1)),this.indexMap.set(t,r),r}},{key:"free",value:function(t){var e=this.indexMap.get(t);if(e!==void 0){this.indexMap.delete(t),this.freeIndices.push(e);for(var r=e*this.TEXELS_PER_ITEM*4,i=0;i<this.TEXELS_PER_ITEM*4;i++)this.data[r+i]=0;this.markDirty(e)}}},{key:"getIndex",value:function(t){var e;return(e=this.indexMap.get(t))!==null&&e!==void 0?e:-1}},{key:"has",value:function(t){return this.indexMap.has(t)}},{key:"markDirty",value:function(t){this.dirty=!0,this.dirtyRangeStart=Math.min(this.dirtyRangeStart,t),this.dirtyRangeEnd=Math.max(this.dirtyRangeEnd,t+1)}},{key:"upload",value:function(){if(!(!this.dirty||!this.texture)){var t=this.gl,e=this.textureWidth;t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,this.texture);var r=this.dirtyRangeStart*this.TEXELS_PER_ITEM,i=Math.min(this.dirtyRangeEnd*this.TEXELS_PER_ITEM,this.capacity*this.TEXELS_PER_ITEM);if(r<i)for(var o=Math.floor(r/e),s=Math.floor((i-1)/e),l=o;l<=s;l++){var u=l*e,d=Math.min(u+e,this.capacity*this.TEXELS_PER_ITEM),c=Math.max(r,u),p=Math.min(i,d);if(c<p){var v=c-u,f=p-c,b=this.data.subarray(c*4,p*4);t.texSubImage2D(t.TEXTURE_2D,0,v,l,f,1,t.RGBA,t.FLOAT,b)}}t.bindTexture(t.TEXTURE_2D,null),this.dirty=!1,this.dirtyRangeStart=1/0,this.dirtyRangeEnd=-1}}},{key:"bind",value:function(t){var e=this.gl;e.activeTexture(e.TEXTURE0+t),e.bindTexture(e.TEXTURE_2D,this.texture)}},{key:"getTexture",value:function(){return this.texture}},{key:"getCapacity",value:function(){return this.capacity}},{key:"getTextureWidth",value:function(){return this.textureWidth}},{key:"getTextureHeight",value:function(){return this.textureHeight}},{key:"getTexelsPerItem",value:function(){return this.TEXELS_PER_ITEM}},{key:"getCount",value:function(){return this.indexMap.size}},{key:"getHighWaterMark",value:function(){return this.nextIndex}},{key:"isDirty",value:function(){return this.dirty}},{key:"clear",value:function(){this.indexMap.clear(),this.freeIndices=[],this.nextIndex=0,this.data.fill(0),this.dirty=!0,this.dirtyRangeStart=0,this.dirtyRangeEnd=this.capacity}},{key:"restore",value:function(){this.createTexture(),this.dirty=!1,this.dirtyRangeStart=1/0,this.dirtyRangeEnd=-1}},{key:"kill",value:function(){this.texture&&(this.gl.deleteTexture(this.texture),this.texture=null),this.indexMap.clear(),this.freeIndices=[]}}])})();function fe(n){var a={},t={},e=0,r=G(n),i;try{for(r.s();!(i=r.n()).done;){var o=i.value,s=G(o.attributes),l;try{for(s.s();!(l=s.n()).done;){var u=l.value,d=u.name.replace(/^a_/,"");d in a||(a[d]=e,t[d]=u,e+=u.size)}}catch(c){s.e(c)}finally{s.f()}}}catch(c){r.e(c)}finally{r.f()}return{floatsPerItem:e,texelsPerItem:Math.max(1,Math.ceil(e/4)),offsets:a,specs:t}}var Un=(function(n){function a(t,e,r){var i;return X(this,a),i=Q(this,a,[t,e.texelsPerItem,r]),i.floatsPerItem=e.floatsPerItem,i}return J(a,n),j(a,[{key:"updateAllAttributes",value:function(e,r){var i=this.indexMap.get(e);i===void 0&&(i=this.allocate(e));for(var o=i*this.TEXELS_PER_ITEM*4,s=Math.min(r.length,this.floatsPerItem),l=0;l<s;l++)this.data[o+l]=r[l];this.markDirty(i)}},{key:"updateAllAttributesAtRow",value:function(e,r){e>=this.capacity&&this.resize(e+1);for(var i=e*this.TEXELS_PER_ITEM*4,o=Math.min(r.length,this.floatsPerItem),s=0;s<o;s++)this.data[i+s]=r[s];this.markDirty(e)}}])})(_t);function Hn(n,a,t){for(var e=[],r=new Set,i=0;i<n.length;i++){var o=n[i],s=G(o.attributes),l;try{for(s.s();!(l=s.n()).done;){var u=l.value,d=u.name.replace(/^a_/,"");if(!r.has(d)){r.add(d);var c=a.offsets[d];if(c!==void 0){var p=t?.get(i);e.push({sourceKey:u.source||d,packedOffset:c,size:u.size,isColor:u.size===4&&!!u.normalized,defaultNum:typeof u.defaultValue=="number"?u.defaultValue:u.defaultValue===!0?1:0,defaultColor:typeof u.defaultValue=="string"?u.defaultValue:"",sourceIndex:i,hasLifecycleHook:!!(p!=null&&p.getAttributeData)})}}}}catch(v){s.e(v)}finally{s.f()}}return e}function Vn(n,a,t,e,r,i){t.fill(0);for(var o=0,s=n.length;o<s;o++){var l=n[o],u=l.packedOffset,d=void 0;if(l.hasLifecycleHook){var c=r.get(l.sourceIndex-i);d=c.getAttributeData(a,l.sourceKey),d===null&&(d=a[l.sourceKey])}else d=a[l.sourceKey];if(l.isColor){var p=typeof d=="string"?d:l.defaultColor||e,v=xe(p),f=Z(v,4),b=f[0],g=f[1],h=f[2],m=f[3];t[u]=b/255,t[u+1]=g/255,t[u+2]=h/255,t[u+3]=m/255}else if(l.size===1)t[u]=typeof d=="number"?d:typeof d=="boolean"?d?1:0:l.defaultNum;else{var x=Array.isArray(d)?d:null;if(x)for(var y=0;y<l.size;y++){var _;t[u+y]=(_=x[y])!==null&&_!==void 0?_:0}}}}var Pn=["r","g","b","a"];function xt(n,a){var t=n.offsets,e=n.specs,r=n.texelsPerItem,i=n.floatsPerItem,o=Object.keys(t);if(o.length===0||i===0)return{fetchCode:"",varyingAssignments:""};var s=a.varPrefix,l=a.baseTexelExpr,u=a.textureWidthUniform,d=a.textureSamplerUniform,c=a.outputPrefix,p=c===void 0?"v_":c,v=[];v.push("  int ".concat(s,"BaseTexel = ").concat(l,";")),v.push("");for(var f=0;f<r;f++)v.push("  ivec2 ".concat(s,"Coord").concat(f," = ivec2((").concat(s,"BaseTexel + ").concat(f,") % ").concat(u,", (").concat(s,"BaseTexel + ").concat(f,") / ").concat(u,");")),v.push("  vec4 ".concat(s,"Texel").concat(f," = texelFetch(").concat(d,", ").concat(s,"Coord").concat(f,", 0);"));v.push("");for(var b=[],g=function(){var y=m[h],_=e[y],T=t[y],R=Math.floor(T/4),E=T%4,D="".concat(s,"Texel").concat(R),P="".concat(s,"Texel").concat(R+1),w="".concat(s,"Fetched_").concat(y);if(_.size===1)v.push("  float ".concat(w," = ").concat(D,".").concat(Pn[E],";"));else if(_.size===4&&E===0)v.push("  vec4 ".concat(w," = ").concat(D,";"));else{var A=E+_.size;if(A<=4){var F="vec".concat(_.size),L=Pn.slice(E,A).join("");v.push("  ".concat(F," ").concat(w," = ").concat(D,".").concat(L,";"))}else{var k=_.size===4?"vec4":"vec".concat(_.size),N=Pn.slice(E).map(function(C){return"".concat(D,".").concat(C)}),z=Pn.slice(0,A-4).map(function(C){return"".concat(P,".").concat(C)}),I=[].concat(H(N),H(z)).join(", ");v.push("  ".concat(k," ").concat(w," = ").concat(k,"(").concat(I,");"))}}b.push("  ".concat(p).concat(y," = ").concat(w,";"))},h=0,m=o;h<m.length;h++)g();return{fetchCode:v.join(`
`),varyingAssignments:b.join(`
`)}}function Ya(n,a,t){if(!(!a||t.type==="sampler2D"))switch(t.type){case"float":n.uniform1f(a,t.value);break;case"int":case"bool":n.uniform1i(a,t.value);break;case"vec2":n.uniform2fv(a,t.value);break;case"vec3":n.uniform3fv(a,t.value);break;case"vec4":n.uniform4fv(a,t.value);break;case"mat3":n.uniformMatrix3fv(a,!1,t.value);break;case"mat4":n.uniformMatrix4fv(a,!1,t.value);break}}var Bs=S(S(S(S(S(S(S(S({},WebGL2RenderingContext.BOOL,1),WebGL2RenderingContext.BYTE,1),WebGL2RenderingContext.UNSIGNED_BYTE,1),WebGL2RenderingContext.SHORT,2),WebGL2RenderingContext.UNSIGNED_SHORT,2),WebGL2RenderingContext.INT,4),WebGL2RenderingContext.UNSIGNED_INT,4),WebGL2RenderingContext.FLOAT,4);function Fn(n){var a=n.match(/^(#version[^\n]*\n)/);return a?a[1]+`#define PICKING_MODE
`+n.slice(a[1].length):`#define PICKING_MODE
`+n}var Pe=(function(){function n(a,t,e){X(this,n),S(this,"floats",new Float32Array),S(this,"ints",new Uint32Array),S(this,"constantArray",new Float32Array),S(this,"capacity",0),S(this,"verticesCount",0),S(this,"bufferGeneration",0),S(this,"uploadedGeneration",new Map),S(this,"constantBufferGeneration",0),S(this,"uploadedConstantGeneration",new Map),S(this,"renderOffset",0),S(this,"renderCount",-1),S(this,"debugStats",{drawCalls:0,verticesDrawn:0,bufferUploadBytes:0}),S(this,"shadersLogged",!1),S(this,"pickProgram",null);var r=this.getDefinition();if(this.VERTICES=r.VERTICES,this.VERTEX_SHADER_SOURCE=r.VERTEX_SHADER_SOURCE,this.FRAGMENT_SHADER_SOURCE=r.FRAGMENT_SHADER_SOURCE,this.UNIFORMS=r.UNIFORMS,this.ATTRIBUTES=r.ATTRIBUTES,this.METHOD=r.METHOD,this.CONSTANT_ATTRIBUTES="CONSTANT_ATTRIBUTES"in r?r.CONSTANT_ATTRIBUTES:[],this.CONSTANT_DATA="CONSTANT_DATA"in r?r.CONSTANT_DATA:[],this.isInstanced="CONSTANT_ATTRIBUTES"in r,this.ATTRIBUTES_ITEMS_COUNT=Vt(this.ATTRIBUTES),this.STRIDE=this.VERTICES*this.ATTRIBUTES_ITEMS_COUNT,this.renderer=e,this.normalProgram=this.getProgramInfo("normal",a,r.VERTEX_SHADER_SOURCE,r.FRAGMENT_SHADER_SOURCE,null),this.pickProgram=this.getProgramInfo("pick",a,Fn(r.VERTEX_SHADER_SOURCE),Fn(r.FRAGMENT_SHADER_SOURCE),null),this.isInstanced){var i=Vt(this.CONSTANT_ATTRIBUTES);if(this.CONSTANT_DATA.length!==this.VERTICES)throw new Error("Program: error while getting constant data (expected ".concat(this.VERTICES," items, received ").concat(this.CONSTANT_DATA.length," instead)"));this.constantArray=new Float32Array(this.CONSTANT_DATA.length*i);for(var o=0;o<this.CONSTANT_DATA.length;o++){var s=this.CONSTANT_DATA[o];if(s.length!==i)throw new Error("Program: error while getting constant data (one vector has ".concat(s.length," items instead of ").concat(i,")"));for(var l=0;l<s.length;l++)this.constantArray[o*i+l]=s[l]}this.STRIDE=this.ATTRIBUTES_ITEMS_COUNT}}return j(n,[{key:"kill",value:function(){zn(this.normalProgram),this.pickProgram&&zn(this.pickProgram)}},{key:"resetDebugStats",value:function(){this.debugStats.drawCalls=0,this.debugStats.verticesDrawn=0,this.debugStats.bufferUploadBytes=0}},{key:"getProgramInfo",value:function(t,e,r,i,o){var s=e.createBuffer();if(s===null)throw new Error("Program: error while creating the WebGL buffer.");var l=qt(e,r),u=Yt(e,i),d=Kt(e,[l,u]),c={};this.UNIFORMS.forEach(function(f){var b=e.getUniformLocation(d,f);b&&(c[f]=b)});var p={};this.ATTRIBUTES.forEach(function(f){p[f.name]=e.getAttribLocation(d,f.name)});var v;if(this.isInstanced&&(this.CONSTANT_ATTRIBUTES.forEach(function(f){p[f.name]=e.getAttribLocation(d,f.name)}),v=e.createBuffer(),v===null))throw new Error("Program: error while creating the WebGL constant buffer.");return{name:t,program:d,gl:e,frameBuffer:o,buffer:s,constantBuffer:v||{},uniformLocations:c,attributeLocations:p,isPicking:t==="pick",vertexShader:l,fragmentShader:u}}},{key:"bindProgram",value:function(t){var e=this,r=0,i=t.gl,o=t.buffer;if(this.isInstanced){if(i.bindBuffer(i.ARRAY_BUFFER,t.constantBuffer),r=0,this.CONSTANT_ATTRIBUTES.forEach(function(d){return r+=e.bindAttribute(d,t,r,!1)}),this.uploadedConstantGeneration.get(t.constantBuffer)!==this.constantBufferGeneration){var l;i.bufferData(i.ARRAY_BUFFER,this.constantArray,i.STATIC_DRAW),this.uploadedConstantGeneration.set(t.constantBuffer,this.constantBufferGeneration),(l=this.renderer)!==null&&l!==void 0&&l.getSetting("DEBUG_logRenderStats")&&(this.debugStats.bufferUploadBytes+=this.constantArray.byteLength)}if(i.bindBuffer(i.ARRAY_BUFFER,t.buffer),r=this.renderOffset*this.ATTRIBUTES_ITEMS_COUNT*Float32Array.BYTES_PER_ELEMENT,this.ATTRIBUTES.forEach(function(d){return r+=e.bindAttribute(d,t,r,!0)}),this.uploadedGeneration.get(o)!==this.bufferGeneration){var u;i.bufferData(i.ARRAY_BUFFER,this.floats,i.DYNAMIC_DRAW),this.uploadedGeneration.set(o,this.bufferGeneration),(u=this.renderer)!==null&&u!==void 0&&u.getSetting("DEBUG_logRenderStats")&&(this.debugStats.bufferUploadBytes+=this.floats.byteLength)}}else if(i.bindBuffer(i.ARRAY_BUFFER,o),r=0,this.ATTRIBUTES.forEach(function(d){return r+=e.bindAttribute(d,t,r)}),this.uploadedGeneration.get(o)!==this.bufferGeneration){var s;i.bufferData(i.ARRAY_BUFFER,this.floats,i.DYNAMIC_DRAW),this.uploadedGeneration.set(o,this.bufferGeneration),(s=this.renderer)!==null&&s!==void 0&&s.getSetting("DEBUG_logRenderStats")&&(this.debugStats.bufferUploadBytes+=this.floats.byteLength)}i.bindBuffer(i.ARRAY_BUFFER,null)}},{key:"unbindProgram",value:function(t){var e=this;this.isInstanced?(this.CONSTANT_ATTRIBUTES.forEach(function(r){return e.unbindAttribute(r,t,!1)}),this.ATTRIBUTES.forEach(function(r){return e.unbindAttribute(r,t,!0)})):this.ATTRIBUTES.forEach(function(r){return e.unbindAttribute(r,t)})}},{key:"bindAttribute",value:function(t,e,r,i){var o=Bs[t.type];if(typeof o!="number")throw new Error('Program.bind: yet unsupported attribute type "'.concat(t.type,'"'));var s=e.attributeLocations[t.name],l=e.gl;if(s!==-1){l.enableVertexAttribArray(s);var u=this.isInstanced?(i?this.ATTRIBUTES_ITEMS_COUNT:Vt(this.CONSTANT_ATTRIBUTES))*Float32Array.BYTES_PER_ELEMENT:this.ATTRIBUTES_ITEMS_COUNT*Float32Array.BYTES_PER_ELEMENT;l.vertexAttribPointer(s,t.size,t.type,t.normalized||!1,u,r),this.isInstanced&&i&&l.vertexAttribDivisor(s,1)}return t.size*o}},{key:"unbindAttribute",value:function(t,e,r){var i=e.attributeLocations[t.name],o=e.gl;i!==-1&&(o.disableVertexAttribArray(i),this.isInstanced&&r&&o.vertexAttribDivisor(i,0))}},{key:"reallocate",value:function(t){t!==this.capacity&&(this.capacity=t,this.verticesCount=this.VERTICES*t,this.floats=new Float32Array(this.isInstanced?this.capacity*this.ATTRIBUTES_ITEMS_COUNT:this.verticesCount*this.ATTRIBUTES_ITEMS_COUNT),this.ints=new Uint32Array(this.floats.buffer),this.invalidateBuffers())}},{key:"invalidateBuffers",value:function(){this.bufferGeneration++,this.constantBufferGeneration++}},{key:"hasNothingToRender",value:function(){return this.verticesCount===0}},{key:"setTypedUniform",value:function(t,e){var r;Ya(e.gl,(r=e.uniformLocations[t.name])!==null&&r!==void 0?r:null,t)}},{key:"renderProgram",value:function(t,e){var r=e.gl,i=e.program,o=e.isPicking;o?r.disable(r.BLEND):r.enable(r.BLEND),r.useProgram(i),this.setUniforms(t,e),this.drawWebGL(this.METHOD,e)}},{key:"render",value:function(t,e,r){var i;if(!this.shadersLogged&&(i=this.renderer)!==null&&i!==void 0&&i.getSetting("DEBUG_logShaders")&&(this.shadersLogged=!0,console.log("[sigma] DEBUG_logShaders: ".concat(this.constructor.name),{normal:{vertexShaderSource:this.VERTEX_SHADER_SOURCE,fragmentShaderSource:this.FRAGMENT_SHADER_SOURCE},pick:{vertexShaderSource:Fn(this.VERTEX_SHADER_SOURCE),fragmentShaderSource:Fn(this.FRAGMENT_SHADER_SOURCE)}})),!this.hasNothingToRender()){this.renderOffset=e??0,this.renderCount=r??-1;var o=this.normalProgram.gl;if(o.bindFramebuffer(o.FRAMEBUFFER,null),o.viewport(0,0,t.width*t.pixelRatio,t.height*t.pixelRatio),this.bindProgram(this.normalProgram),this.renderProgram(t,this.normalProgram),this.unbindProgram(this.normalProgram),this.pickProgram&&t.pickingFrameBuffer){var s=Math.ceil(t.width*t.pixelRatio/t.downSizingRatio),l=Math.ceil(t.height*t.pixelRatio/t.downSizingRatio);o.bindFramebuffer(o.FRAMEBUFFER,t.pickingFrameBuffer),o.viewport(0,0,s,l),this.bindProgram(this.pickProgram),this.renderProgram(t,this.pickProgram),this.unbindProgram(this.pickProgram),o.bindFramebuffer(o.FRAMEBUFFER,null),o.viewport(0,0,t.width*t.pixelRatio,t.height*t.pixelRatio)}}}},{key:"drawWebGL",value:function(t,e){var r,i=e.gl,o=this.renderCount>=0?this.renderCount:this.capacity;(r=this.renderer)!==null&&r!==void 0&&r.getSetting("DEBUG_logRenderStats")&&(this.debugStats.drawCalls++,this.debugStats.verticesDrawn+=o*this.VERTICES),this.isInstanced?i.drawArraysInstanced(t,0,this.VERTICES,o):i.drawArrays(t,this.renderOffset*this.VERTICES,o*this.VERTICES)}}])})(),He=2,Jt=7,Oi={below:0,above:1,left:2,right:3};function Ws(){var n=`#version 300 es
precision highp float;

uniform mat3 u_matrix;
uniform vec2 u_resolution;
uniform float u_labelPixelSnapping;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
uniform float u_pixelRatio;
uniform float u_labelMargin;
uniform float u_zoomLabelSizeRatio;

uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_nodeFrameTexture;
uniform int u_nodeFrameTextureWidth;

// Atlas size is fixed at 2048\xD72048 \u2014 matches AttachmentManager.ATLAS_SIZE.
uniform sampler2D u_atlasTexture;
const vec2 u_atlasSize = vec2(2048.0);

// Per-instance
in float a_nodeIndex;           // node-data texture index
in vec4 a_atlasRect;            // x, y, width, height in atlas pixels
in vec2 a_attachmentSize;       // attachment dimensions (CSS px)
in float a_positionMode;        // label position: 0=right 1=left 2=above 3=below 4=over
in float a_attachmentPlacement; // 0=below 1=above 2=left 3=right (relative to label)
in float a_labelWidth;          // label width (CSS px)
in float a_labelHeight;         // label height: font line box (CSS px)
in float a_textHeight;          // actual glyph height (CSS px)
in float a_labelAngle;          // label rotation angle (radians)

// Per-vertex (constant)
in vec2 a_quadCorner;           // [-1,-1], [1,-1], [-1,1], [1,1]

out vec2 v_texCoord;

`.concat(me,`
`).concat(Le,`
`).concat(Ue,`
`).concat(Wn,`
`).concat(We,`

void main() {
  int nodeIdx = int(a_nodeIndex);

  // Node data: (x, y, size, shapeId).
  vec4 nodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  vec2 nodePos = nodeData.xy;
  float nodeSize = nodeData.z;

  // Normalized edge distance from the shared frame texture (the frame-pass ran
  // the SDF search once; we just read the result).
  float edgeDist = readFrameTexel(u_nodeFrameTexture, u_nodeFrameTextureWidth, nodeIdx).r;

  // Per-node label rotation alignment: 0 = viewport, 1 = label turns with camera.
  float labelRotation = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx).g;

  vec3 nodeClip = u_matrix * vec3(nodePos, 1.0);

  // Node radius in physical pixels (matches label/background).
  float matrixScaleX = length(vec2(u_matrix[0][0], u_matrix[1][0]));
  float nodeRadiusGraphSpace = nodeSize * u_correctionRatio / u_sizeRatio * 2.0;
  float nodeRadiusPixels = nodeRadiusGraphSpace * matrixScaleX * u_resolution.x / 2.0;

  // CSS-px inputs -> physical px, scaled by the zoom-dependent label ratio, so
  // the attachment stays glued to the label box exactly as the label scales.
  float zoomScale = u_zoomLabelSizeRatio;
  vec2 labelHalf = vec2(a_labelWidth, a_labelHeight) * 0.5 * zoomScale * u_pixelRatio;
  vec2 attachHalf = a_attachmentSize * 0.5 * zoomScale * u_pixelRatio;
  float gap = `).concat(He.toFixed(1),` * zoomScale * u_pixelRatio;
  float labelMargin = u_labelMargin * zoomScale * u_pixelRatio;

  // Graph-aligned labels add the camera angle so the attachment orbits with the box.
  mat2 labelRotMat = rotate2D(a_labelAngle - labelRotation * u_cameraAngle);

  // Label box center relative to the node center (pre-rotation). The shape-aware
  // edge distance comes from the frame texture, so placement matches the label.
  vec2 boxCenter = vec2(0.0);
  if (a_positionMode < 4.0) {
    float labelStart = nodeRadiusPixels * edgeDist + labelMargin;
    float textHalf = a_textHeight * 0.5 * zoomScale * u_pixelRatio;
    boxCenter = labelBoxCenter(a_positionMode, labelStart, labelHalf, textHalf);
  }

  // Horizontal anchor of below/above attachments tracks the label position, so
  // the attachment hangs from the label edge nearest the node (or is centered
  // when the label itself is node-centered): right->left, left->right, else center.
  float anchorX = 0.0;
  if (a_positionMode < 0.5) anchorX = -labelHalf.x + attachHalf.x;       // right label
  else if (a_positionMode < 1.5) anchorX = labelHalf.x - attachHalf.x;   // left label

  // Attachment center relative to the box (pre-rotation, Y-down). This offset
  // depends only on the box, the gap and the attachment size \u2014 never the shape.
  vec2 attachCenter;
  if (a_attachmentPlacement < 0.5) {
    // below
    attachCenter = boxCenter + vec2(anchorX, labelHalf.y + gap + attachHalf.y);
  } else if (a_attachmentPlacement < 1.5) {
    // above
    attachCenter = boxCenter + vec2(anchorX, -(labelHalf.y + gap + attachHalf.y));
  } else if (a_attachmentPlacement < 2.5) {
    // left, top-aligned
    attachCenter = boxCenter + vec2(-(labelHalf.x + gap + attachHalf.x), -labelHalf.y + attachHalf.y);
  } else {
    // right, top-aligned
    attachCenter = boxCenter + vec2(labelHalf.x + gap + attachHalf.x, -labelHalf.y + attachHalf.y);
  }

  // Rotate the whole assembly by the label angle, around the node center.
  vec2 rotatedCenter = labelRotMat * attachCenter;
  vec2 cornerOffset = labelRotMat * (a_quadCorner * attachHalf);

  // Node center in screen px (Y-down).
  vec2 nodeScreen = vec2(
    (nodeClip.x + 1.0) * u_resolution.x,
    (1.0 - nodeClip.y) * u_resolution.y
  ) * 0.5;

  // Snap node center to the pixel grid so label/backdrop/attachment move as one.
  vec2 snapDelta = (round(nodeScreen) - nodeScreen) * u_labelPixelSnapping;

  // Snap the quad's top-left to integer pixels so atlas texels map 1:1.
  vec2 centerScreen = nodeScreen + rotatedCenter + snapDelta;
  vec2 topLeft = centerScreen - attachHalf;
  topLeft = mix(topLeft, round(topLeft), u_labelPixelSnapping);
  centerScreen = topLeft + attachHalf;

  vec2 vertexScreen = centerScreen + cornerOffset;
  gl_Position = vec4(
    vertexScreen.x * 2.0 / u_resolution.x - 1.0,
    1.0 - vertexScreen.y * 2.0 / u_resolution.y,
    0.0, 1.0
  );

  vec2 texOrigin = a_atlasRect.xy / u_atlasSize;
  vec2 texSize = a_atlasRect.zw / u_atlasSize;
  vec2 uv = (a_quadCorner + 1.0) / 2.0;
  v_texCoord = texOrigin + uv * texSize;
}
`);return n}var Us=`#version 300 es
precision highp float;

uniform sampler2D u_atlasTexture;

in vec2 v_texCoord;

layout(location = 0) out vec4 fragColor;
#ifdef PICKING_MODE
layout(location = 1) out vec4 pickColor;
#endif

void main() {
  // Canvas textures are premultiplied; output directly for (ONE, 1-SRC_ALPHA) blending
  vec4 color = texture(u_atlasTexture, v_texCoord);
  if (color.a < 0.01) discard;
  fragColor = color;
#ifdef PICKING_MODE
  pickColor = vec4(0.0); // Attachments are not pickable
#endif
}
`;function Hs(n,a,t,e){var r,i,o=e.label,s=o===void 0?{}:o,l=(r=s.margin)!==null&&r!==void 0?r:Be,u=(i=s.zoomToLabelSizeRatioFunction)!==null&&i!==void 0?i:function(){return 1},d=Ws(),c=Us,p=(function(v){function f(){var b;X(this,f);for(var g=arguments.length,h=new Array(g),m=0;m<g;m++)h[m]=arguments[m];return b=Q(this,f,[].concat(h)),S(b,"totalCount",0),S(b,"bufferCapacity",0),b}return J(f,v),j(f,[{key:"getDefinition",value:function(){var g=WebGL2RenderingContext,h=g.FLOAT,m=g.TRIANGLE_STRIP;return{VERTICES:4,VERTEX_SHADER_SOURCE:d,FRAGMENT_SHADER_SOURCE:c,METHOD:m,UNIFORMS:["u_matrix","u_resolution","u_labelPixelSnapping","u_sizeRatio","u_correctionRatio","u_cameraAngle","u_pixelRatio","u_labelMargin","u_zoomLabelSizeRatio","u_nodeDataTexture","u_nodeDataTextureWidth","u_nodeFrameTexture","u_nodeFrameTextureWidth","u_atlasTexture"],ATTRIBUTES:[{name:"a_nodeIndex",size:1,type:h},{name:"a_atlasRect",size:4,type:h},{name:"a_attachmentSize",size:2,type:h},{name:"a_positionMode",size:1,type:h},{name:"a_attachmentPlacement",size:1,type:h},{name:"a_labelWidth",size:1,type:h},{name:"a_labelHeight",size:1,type:h},{name:"a_textHeight",size:1,type:h},{name:"a_labelAngle",size:1,type:h}],CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:h}],CONSTANT_DATA:[[-1,-1],[1,-1],[-1,1],[1,1]]}}},{key:"processAttachment",value:function(g,h){var m=this.floats,x=g*this.STRIDE;m[x++]=h.nodeIndex,m[x++]=h.atlasX,m[x++]=h.atlasY,m[x++]=h.atlasW,m[x++]=h.atlasH,m[x++]=h.attachWidth,m[x++]=h.attachHeight,m[x++]=h.positionMode,m[x++]=h.attachmentPlacement,m[x++]=h.labelWidth,m[x++]=h.labelHeight,m[x++]=h.textHeight,m[x++]=h.labelAngle}},{key:"setUniforms",value:function(g,h){var m=h.gl,x=h.uniformLocations;m.uniformMatrix3fv(x.u_matrix,!1,g.matrix),m.uniform2f(x.u_resolution,g.width*g.pixelRatio,g.height*g.pixelRatio),m.uniform1f(x.u_labelPixelSnapping,g.labelPixelSnapping),m.uniform1f(x.u_sizeRatio,g.sizeRatio),m.uniform1f(x.u_correctionRatio,g.correctionRatio),m.uniform1f(x.u_cameraAngle,g.cameraAngle),m.uniform1f(x.u_pixelRatio,g.pixelRatio),m.uniform1f(x.u_labelMargin,f.labelMargin),m.uniform1f(x.u_zoomLabelSizeRatio,1/u(g.zoomRatio)),m.uniform1i(x.u_nodeDataTexture,g.nodeDataTextureUnit),m.uniform1i(x.u_nodeDataTextureWidth,g.nodeDataTextureWidth),m.uniform1i(x.u_nodeFrameTexture,g.nodeFrameTextureUnit),m.uniform1i(x.u_nodeFrameTextureWidth,g.nodeFrameTextureWidth),m.uniform1i(x.u_atlasTexture,Jt)}},{key:"reallocateAttachments",value:function(g){this.totalCount=g,g>this.bufferCapacity&&(this.bufferCapacity=Math.max(g,Math.ceil(this.bufferCapacity*1.5)||10),te(f,"reallocate",this,3)([this.bufferCapacity]))}},{key:"hasNothingToRender",value:function(){return this.totalCount===0}},{key:"drawWebGL",value:function(g,h){var m=h.gl;this.totalCount!==0&&m.drawArraysInstanced(g,0,this.VERTICES,this.totalCount)}}])})(Pe);return S(p,"labelMargin",l),new p(n,a,t)}var Me=5;function Xn(n,a){return[].concat(H(a),H(n.map(function(t){var e;return{attributes:(e=t.attributes)!==null&&e!==void 0?e:[]}})))}function Tt(n,a){var t=fe(Xn(n,a)),e=new Set(n.flatMap(function(u){var d;return(d=u.attributes)!==null&&d!==void 0?d:[]}).map(function(u){return u.name.replace(/^a_/,"")})),r={},i={},o=G(e),s;try{for(o.s();!(s=o.n()).done;){var l=s.value;r[l]=t.offsets[l],i[l]=t.specs[l]}}catch(u){o.e(u)}finally{o.f()}return O(O({},t),{},{offsets:r,specs:i})}function Ka(n,a){var t=new Set(["u_matrix","u_sizeRatio","u_correctionRatio","u_cameraAngle","u_pickingPadding","u_nodeDataTexture","u_layerAttributeTexture"]),e=new Set,r=n.flatMap(function(v){return v.uniforms}).filter(function(v){return t.has(v.name)||e.has(v.name)?!1:(e.add(v.name),!0)}).map(function(v){return"uniform ".concat(v.type," ").concat(v.name,";")}).join(`
`),i=a.flatMap(function(v){return v.uniforms}).filter(function(v){return t.has(v.name)||e.has(v.name)?!1:(e.add(v.name),!0)}).map(function(v){return"uniform ".concat(v.type," ").concat(v.name,";")}).join(`
`),o=Xn(n,a),s=new Set,l=o.flatMap(function(v){return v.attributes}).filter(function(v){var f=v.name.replace(/^a_/,"");return s.has(f)?!1:(s.add(f),!0)}).map(function(v){var f=v.name.replace(/^a_/,""),b=v.size===1?"float":"vec".concat(v.size);return"out ".concat(b," v_").concat(f,";")}).join(`
`),u=xt(fe(o),{varPrefix:"layer",baseTexelExpr:"nodeIdx * u_layerAttributeTexelsPerNode",textureWidthUniform:"u_layerAttributeTextureWidth",textureSamplerUniform:"u_layerAttributeTexture"}),d=u.fetchCode,c=u.varyingAssignments,p=`#version 300 es

// Standard node attributes (per instance) - minimal buffer usage
in float a_nodeIndex;  // Index into node data texture AND layer attribute texture
in vec4 a_id;          // Node ID for picking
in float a_opacity;    // Node opacity, applied once to the final fragment

// Constant attributes (per vertex, same for all instances)
in vec2 a_quadCorner;  // (-1,-1), (1,-1), (1,1), (-1,1) for quad corners

// Standard uniforms
uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
#ifdef PICKING_MODE
uniform float u_pickingPadding;
#endif
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;

// Layer attribute texture uniforms
uniform sampler2D u_layerAttributeTexture;
uniform int u_layerAttributeTextureWidth;
uniform int u_layerAttributeTexelsPerNode;

`.concat(r,`
`).concat(i,`

// Standard varyings
out vec2 v_uv;                    // Normalized coordinates [-1, 1]
out vec4 v_id;
out float v_opacity;
out float v_antialiasingWidth;    // Width for antialiasing in UV space
out float v_pixelSize;            // Node size in pixels (for pixel-mode borders)
out float v_pixelToUV;            // Conversion factor: multiply by this to convert screen pixels to UV units
out float v_shapeId;              // Shape ID for multi-shape programs

// Layer varyings
`).concat(l,`

// Node-data fetch helpers (geometry texel + rotation-flags texel)
`).concat(me,`
`).concat(Le,`

void main() {
  // Fetch node geometry: vec4(x, y, size, shapeId).
  int nodeIdx = int(a_nodeIndex);

  // Hidden nodes are flagged with a negative row by NodeProgram.process(). Push
  // the whole quad outside the clip volume: every vertex lands at the same
  // out-of-range position, so the primitive is fully clipped and rasterizes
  // nothing \u2014 neither to the frame buffer nor to the picking buffer.
  if (nodeIdx < 0) {
    gl_Position = vec4(2.0, 0.0, 0.0, 1.0);
    v_id = vec4(0.0);
    return;
  }

  vec4 nodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  vec2 a_position = nodeData.xy;
  float a_size = nodeData.z;
  v_shapeId = nodeData.w;  // Pass shape ID to fragment shader

  // Per-node rotation alignment: 0 = viewport (screen-upright), 1 = graph.
  float nodeRotation = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx).r;

`).concat(d,`

  // Calculate the actual size in pixels
  float size = a_size * u_correctionRatio / u_sizeRatio * 2.0;

  // In PICKING_MODE, inflate the quad by nodePickingPadding pixels on each side
  #ifdef PICKING_MODE
    float paddedSize = size + u_pickingPadding * u_correctionRatio;
    vec2 offset = a_quadCorner * paddedSize;
  #else
    vec2 offset = a_quadCorner * size;
  #endif
  // Counter-rotate the quad offset so viewport-aligned nodes stay upright as the
  // camera turns. Graph-aligned nodes (nodeRotation=1) skip it and turn with the
  // camera. The angle scales by (1 - nodeRotation) so both fall out of one path.
  {
    float ca = u_cameraAngle * (1.0 - nodeRotation);
    float c = cos(ca);
    float s = sin(ca);
    offset = mat2(c, s, -s, c) * offset;
  }
  vec2 position = a_position + offset;

  gl_Position = vec4(
    (u_matrix * vec3(position, 1)).xy,
    0,
    1
  );

  // In PICKING_MODE, UV is scaled beyond [-1, 1] to match the inflated quad
  #ifdef PICKING_MODE
    v_uv = a_quadCorner * (paddedSize / size);
  #else
    v_uv = a_quadCorner;
  #endif

  // Pass ID to fragment shader
  v_id = a_id;
  v_opacity = a_opacity;

  // Pass pixel size for layers that need pixel-mode calculations
  // Multiply by 2 because 'size' is half-width (offset from center), not full diameter
  v_pixelSize = size * 2.0;

  // Conversion factor from screen pixels to UV units
  // Same derivation as v_antialiasingWidth which represents ~1 pixel in UV space
  // P pixels in UV space = P * u_correctionRatio / size
  v_pixelToUV = u_correctionRatio / size;

  // We use an antialiasing width of 1px (so v_pixelToUV)
  v_antialiasingWidth = v_pixelToUV;

  // Pass layer attributes to fragment shader (fetched from texture)
`).concat(c,`
}
`);return p}function Za(n,a,t){var e=arguments.length>3&&arguments[3]!==void 0?arguments[3]:!0,r=a.map(function(f,b){var g="layer_".concat(f.name),h=[].concat(H(f.attributes.map(function(m){return"v_".concat(m.name.replace(/^a_/,""))})),H(f.uniforms.map(function(m){return m.name}))).join(", ");return"  // Layer ".concat(b+1,": ").concat(f.name,`
  color = blendOver(color, `).concat(g,"(").concat(h,"));")}).join(`

`),i=new Set(["u_correctionRatio"]),o=new Set,s=n.flatMap(function(f){return f.uniforms}).filter(function(f){return i.has(f.name)||o.has(f.name)?!1:(o.add(f.name),!0)}).map(function(f){return"uniform ".concat(f.type," ").concat(f.name,";")}).join(`
`),l=a.flatMap(function(f){return f.uniforms}).filter(function(f){return i.has(f.name)||o.has(f.name)?!1:(o.add(f.name),!0)}).map(function(f){return"uniform ".concat(f.type," ").concat(f.name,";")}).join(`
`),u=new Set,d=Xn(n,a).flatMap(function(f){return f.attributes}).filter(function(f){var b=f.name.replace(/^a_/,"");return u.has(b)?!1:(u.add(b),!0)}).map(function(f){var b=f.name.replace(/^a_/,""),g=f.size===1?"float":"vec".concat(f.size);return"in ".concat(g," v_").concat(b,";")}).join(`
`),c=Zt(n),p=Wa(n,t),v=`#version 300 es
precision highp float;

// Standard varyings
in vec2 v_uv;
in vec4 v_id;
in float v_opacity;
in float v_antialiasingWidth;
in float v_pixelSize;
in float v_pixelToUV;
in float v_shapeId;  // Shape ID for multi-shape programs

// Standard uniforms (needed for some layer calculations like pixel-mode borders)
uniform float u_correctionRatio;
#ifdef PICKING_MODE
uniform float u_pickingPadding;
#endif

// Shape uniforms
`.concat(s,`

// Layer uniforms
`).concat(l,`

// Layer varyings
`).concat(d,`

// Fragment output (single target - picking handled via separate pass)
out vec4 fragColor;

// LayerContext struct - provides rendering context to all layers
struct LayerContext {
  float sdf;             // Signed distance from shape boundary (negative inside)
  vec2 uv;               // UV coordinates [-1, 1], center at (0,0)
  float shapeSize;       // Effective shape size (~diameter) in UV space (1.0 - aaWidth)
  float shapeHalfSize;   // Effective shape half size (~radius) in UV space
  float pixelSize;       // Node full size (~diameter) in screen pixels
  float aaWidth;         // Anti-aliasing width for smooth transitions
  float correctionRatio; // Scaling factor for consistent rendering across zoom levels
  float pixelToUV;       // Conversion factor: multiply screen pixels by this to get UV units
  float inradiusFactor;  // Ratio of inradius to circumradius (shape depth factor)
};

LayerContext context;  // Global instance, populated before layer calls

// Alpha "over" compositing for layer blending
vec4 blendOver(vec4 bg, vec4 fg) {
  float a = fg.a;
  return vec4(mix(bg.rgb, fg.rgb, a), bg.a + a * (1.0 - bg.a));
}

// SDF shape functions
`).concat(c,`

// Shape selector function (sets context.sdf and context.inradiusFactor)
`).concat(p,`

// Layer functions
`).concat(a.map(function(f){return f.glsl}).join(`

`),`

void main() {
  // 1. Setup LayerContext (available to all layer functions)
  context.shapeSize = 1.0 - v_antialiasingWidth;
  context.shapeHalfSize = context.shapeSize * 0.5;
  context.pixelSize = v_pixelSize;
  context.uv = v_uv;
  context.aaWidth = v_antialiasingWidth;
  context.correctionRatio = u_correctionRatio;
  context.pixelToUV = v_pixelToUV;

  // Query shape SDF based on shapeId (sets context.sdf and context.inradiusFactor)
  queryNodeSDF(int(v_shapeId), v_uv, context.shapeSize);

  // 2. Early discard for pixels fully outside the shape (with AA margin)
  // In PICKING_MODE, allow extra fragments up to the picking padding distance
  #ifdef PICKING_MODE
    if (context.sdf > u_pickingPadding * v_pixelToUV + context.aaWidth) discard;
  #else
    if (context.sdf > context.aaWidth) discard;
  #endif

  // 3. Apply layers sequentially with "over" compositing
  vec4 color = vec4(0.0);

`).concat(r,`

  #ifdef PICKING_MODE
    // Picking pass: output node ID for pixels within the picking area.
    if (context.sdf > u_pickingPadding * v_pixelToUV) discard;
    fragColor = v_id;
  #else
`).concat(e?`    // Visual pass: apply antialiasing at shape boundary, node opacity once
    // smoothstep provides smooth transition from opaque to transparent
    float alpha = smoothstep(context.aaWidth, -context.aaWidth, context.sdf) * v_opacity;`:`    // Visual pass: hard-edged (no anti-aliasing gradient) shape boundary, node opacity applied once
    float alpha = (context.sdf < 0.0 ? 1.0 : 0.0) * v_opacity;`,`
    // Mix with transparent to fade both color AND alpha together (avoids bright halo)
    fragColor = mix(vec4(0.0), color, alpha);
  #endif
}
`);return v}function $a(n,a){var t=new Set;return t.add("u_matrix"),t.add("u_sizeRatio"),t.add("u_correctionRatio"),t.add("u_cameraAngle"),t.add("u_pickingPadding"),t.add("u_nodeDataTexture"),t.add("u_nodeDataTextureWidth"),t.add("u_layerAttributeTexture"),t.add("u_layerAttributeTextureWidth"),t.add("u_layerAttributeTexelsPerNode"),n.forEach(function(e){e.uniforms.forEach(function(r){return t.add(r.name)})}),a.forEach(function(e){e.uniforms.forEach(function(r){return t.add(r.name)})}),Array.from(t)}function Qa(n){var a=WebGL2RenderingContext,t=a.UNSIGNED_BYTE,e=a.FLOAT;return[{name:"a_nodeIndex",size:1,type:e},{name:"a_id",size:4,type:t,normalized:!0},{name:"a_opacity",size:1,type:e}]}function Nn(n){var a=n.shapes,t=n.layers,e=n.shapeGlobalIds,r=n.antialias,i=r===void 0?!0:r;return{vertexShader:Ka(a,t),fragmentShader:Za(a,t,e,i),uniforms:$a(a,t),attributes:Qa()}}function Bi(n,a,t){var e=Tt(n,a),r=e.specs;return Object.keys(r).map(function(i){return"flat ".concat(t," ").concat(r[i].size===1?"float":"vec".concat(r[i].size)," v_").concat(i,";")}).join(`
`)}function Ja(n){var a,t,e=n.shapes,r=n.layers,i=n.shapeGlobalIds,o=xt(Tt(e,r),{varPrefix:"nodeAttr",baseTexelExpr:"nodeIdx * u_layerAttributeTexelsPerNode",textureWidthUniform:"u_layerAttributeTextureWidth",textureSamplerUniform:"u_layerAttributeTexture"}),s=e.length===1?"float inradiusFactor = ".concat(Y((a=e[0].inradiusFactor)!==null&&a!==void 0?a:1),";"):"float inradiusFactor = ".concat(Y((t=e[0].inradiusFactor)!==null&&t!==void 0?t:1),`;
  switch (int(shapeId)) {
`).concat(e.map(function(u,d){var c,p=i?i[d]:d;return"    case ".concat(p,": inradiusFactor = ").concat(Y((c=u.inradiusFactor)!==null&&c!==void 0?c:1),"; break;")}).join(`
`),`
    default: break;
  }`),l=`#version 300 es

in float a_nodeIndex;
in float a_labelWidth;
in float a_labelHeight;
in float a_textHeight;
in float a_positionMode;
in float a_labelAngle;
in vec4 a_backdropColor;
in vec4 a_backdropShadowColor;
in float a_backdropShadowBlur;
in float a_backdropPadding;
in vec4 a_backdropBorderColor;
in vec4 a_backdropExtra; // [borderWidth, cornerRadius, labelPadding, area]
in vec2 a_labelBoxOffset;
in vec2 a_quadCorner;

uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
uniform vec2 u_resolution;
uniform float u_pixelRatio;
uniform float u_labelMargin;
uniform float u_zoomLabelSizeRatio;
uniform float u_labelPixelSnapping;
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_nodeFrameTexture;
uniform int u_nodeFrameTextureWidth;
uniform sampler2D u_layerAttributeTexture;
uniform int u_layerAttributeTextureWidth;
uniform int u_layerAttributeTexelsPerNode;

out vec2 v_uv;
out vec2 v_nodeCenter;
out float v_nodeRadius;
out vec2 v_labelCenter;
out vec2 v_labelHalfSize;
out float v_aaWidth;
out float v_shapeId;
out float v_nodeRotation;
out float v_labelAngle;
out vec4 v_backdropColor;
out vec4 v_backdropShadowColor;
out float v_backdropShadowBlur;
out float v_backdropPadding;
out vec4 v_backdropBorderColor;
out float v_backdropBorderWidth;
out float v_backdropCornerRadius;
out float v_backdropArea;
`.concat(Bi(e,r,"out"),`

`).concat(me,`
`).concat(Le,`
`).concat(Ue,`

void main() {
  int nodeIdx = int(a_nodeIndex);
`).concat(o.fetchCode,`
`).concat(o.varyingAssignments,`

  // Node data: (x, y, size, shapeId). shapeId (global) is forwarded to the
  // fragment shader, which keeps the shape SDF for the outline.
  vec4 nodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  vec2 nodePosition = nodeData.xy;
  float nodeSize = nodeData.z;
  float shapeId = nodeData.w;

  // Per-node rotation alignment (0 = viewport, 1 = graph). nodeRotation drives
  // the fragment's shape outline; labelRotation turns the label box with camera.
  vec4 nodeFlags = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  float nodeRotation = nodeFlags.r;
  float labelRotation = nodeFlags.g;
  v_nodeRotation = nodeRotation;

  `).concat(On,`
  // CSS pixel attributes are multiplied by u_pixelRatio to match nodeRadiusPixels,
  // which is already in physical pixels (nodeRadiusNDC * u_resolution.x / 2.0).
  float padding = a_backdropPadding * u_pixelRatio;
  float shadowBlur = a_backdropShadowBlur * u_pixelRatio;
  // Unpack a_backdropExtra: [borderWidth, cornerRadius, labelPadding, area]
  float borderWidth = a_backdropExtra.x * u_pixelRatio;
  float cornerRadius = a_backdropExtra.y * u_pixelRatio;
  float labelPad = a_backdropExtra.z * u_pixelRatio;
  float backdropArea = a_backdropExtra.w;
  // Use 2x shadowBlur so the Gaussian fully decays before the quad edge
  float totalExpansion = shadowBlur * 2.0 + borderWidth;
  float enlargedRadius = nodeRadiusPixels + padding;

  // Circumscribed radius for the quad bounds. Non-circular shapes reach past
  // their inradius out to their circumradius (= enlargedRadius / inradiusFactor),
  // in any direction once rotated. The axis-aligned quad must contain that, or
  // the fill/shadow gets clipped (square corners, triangle tip, etc.).
  `).concat(s,`
  float boundRadius = enlargedRadius / inradiusFactor;

  // Apply zoom-dependent label size scaling
  float zoomScale = u_zoomLabelSizeRatio;
  float labelW = a_labelWidth * zoomScale * u_pixelRatio;
  float labelH = a_labelHeight * zoomScale * u_pixelRatio;
  float labelMargin = u_labelMargin * zoomScale * u_pixelRatio;

  // Only apply labelPad when a label is actually present
  float effectiveLabelPad = labelW > 0.0 ? labelPad : 0.0;
  vec2 labelHalfSize = vec2(labelW * 0.5 + effectiveLabelPad, labelH * 0.5 + effectiveLabelPad);
  vec2 labelOffset = vec2(0.0);

  // Effective label angle: intrinsic angle plus the camera angle when the label
  // is graph-aligned, so the box orbits the node in lockstep with the frame-pass.
  float labelAngle = a_labelAngle - labelRotation * u_cameraAngle;
  float la_c = cos(labelAngle);
  float la_s = sin(labelAngle);
  mat2 labelRotMat = mat2(la_c, -la_s, la_s, la_c);

  vec3 nodeClip = u_matrix * vec3(nodePosition, 1.0);
  vec2 snapDelta = vec2(0.0);

  if (labelW > 0.0) {
    // labelW > 0.0 means this node's label is displayed, so the frame-pass wrote
    // its edge distance this frame.
    float edgeDistPixels = nodeRadiusPixels * readFrameTexel(u_nodeFrameTexture, u_nodeFrameTextureWidth, nodeIdx).r;
    // labelMargin matches the label shader's margin (gap from node edge to text)
    float labelStart = edgeDistPixels + labelMargin;
    // Above/below center on the actual glyph height, not the font line box, so
    // the box stays aligned with the rendered text (matches labelBoxCenter()).
    float textHalf = a_textHeight * zoomScale * u_pixelRatio * 0.5;

    // Snap node center to pixel grid so label/backdrop/attachment move as a unit
    vec2 nodeScreen = vec2(
      (nodeClip.x + 1.0) * u_resolution.x,
      (1.0 - nodeClip.y) * u_resolution.y
    ) * 0.5;
    snapDelta = (round(nodeScreen) - nodeScreen) * u_labelPixelSnapping;

    if (a_positionMode < 0.5) {
      // Right: box spans from node center to text end + padding
      float boxRightEdge = labelStart + labelW + labelPad;
      labelOffset = vec2(boxRightEdge * 0.5, 0.0);
      labelHalfSize.x = boxRightEdge * 0.5;
    } else if (a_positionMode < 1.5) {
      // Left: mirror of right
      float boxLeftEdge = labelStart + labelW + labelPad;
      labelOffset = vec2(-boxLeftEdge * 0.5, 0.0);
      labelHalfSize.x = boxLeftEdge * 0.5;
    } else if (a_positionMode < 2.5) {
      // Above: text bottom at labelStart, centered horizontally
      labelOffset = vec2(0.0, -(labelStart + textHalf));
    } else if (a_positionMode < 3.5) {
      // Below: text top at labelStart, centered horizontally
      labelOffset = vec2(0.0, labelStart + textHalf);
    }
    // over (>=4): labelOffset stays (0,0) \u2014 text centered on the node.

    // The attachment-cover shift is in label space (like the attachment itself),
    // so rotate it together with the position offset \u2014 otherwise the box drifts
    // off the attachment as the label angle grows.
    labelOffset = labelRotMat * (labelOffset + a_labelBoxOffset * zoomScale * u_pixelRatio);
  }

  // For node-only mode, zero out label dimensions
  if (backdropArea > 0.5 && backdropArea < 1.5) {
    labelHalfSize = vec2(0.0);
    labelOffset = vec2(0.0);
  }

  vec2 minBound, maxBound;

  bool hasLabelBounds = labelW > 0.0 && (backdropArea > 1.5 || backdropArea < 0.5);

  if (hasLabelBounds) {
    // Union with label bounds (area=both) or label-only bounds (area=label)
    vec2 labelMin, labelMax;

    if (a_labelAngle != 0.0) {
      vec2 corner1 = labelOffset + labelRotMat * vec2(-labelHalfSize.x, -labelHalfSize.y);
      vec2 corner2 = labelOffset + labelRotMat * vec2(labelHalfSize.x, -labelHalfSize.y);
      vec2 corner3 = labelOffset + labelRotMat * vec2(labelHalfSize.x, labelHalfSize.y);
      vec2 corner4 = labelOffset + labelRotMat * vec2(-labelHalfSize.x, labelHalfSize.y);
      labelMin = min(min(corner1, corner2), min(corner3, corner4));
      labelMax = max(max(corner1, corner2), max(corner3, corner4));
    } else {
      labelMin = labelOffset - labelHalfSize;
      labelMax = labelOffset + labelHalfSize;
    }

    if (backdropArea > 1.5) {
      // Label-only: bounds from label rect only
      minBound = labelMin - totalExpansion;
      maxBound = labelMax + totalExpansion;
    } else {
      // Both: union of node + label
      minBound = min(-vec2(boundRadius), labelMin) - totalExpansion;
      maxBound = max(vec2(boundRadius), labelMax) + totalExpansion;
    }
  } else {
    // Node-only or no visible label
    float totalRadius = boundRadius + totalExpansion;
    minBound = -vec2(totalRadius);
    maxBound = vec2(totalRadius);
  }

  vec2 quadSize = maxBound - minBound;
  vec2 quadCenter = (minBound + maxBound) * 0.5;

  vec2 localPos = quadCenter + a_quadCorner * quadSize * 0.5 + snapDelta;
  vec2 ndcOffset = localPos * 2.0 / u_resolution;
  ndcOffset.y = -ndcOffset.y;

  gl_Position = vec4(nodeClip.xy + ndcOffset, 0.0, 1.0);

  v_uv = localPos;
  v_nodeCenter = vec2(0.0);
  v_nodeRadius = nodeRadiusPixels;
  v_labelCenter = labelOffset;
  v_labelHalfSize = labelHalfSize;
  v_aaWidth = 1.0;
  v_shapeId = shapeId;
  v_labelAngle = labelAngle;
  v_backdropColor = a_backdropColor;
  v_backdropShadowColor = a_backdropShadowColor;
  v_backdropShadowBlur = a_backdropShadowBlur;
  v_backdropPadding = a_backdropPadding;
  v_backdropBorderColor = a_backdropBorderColor;
  v_backdropBorderWidth = borderWidth;
  v_backdropCornerRadius = cornerRadius;
  v_backdropArea = backdropArea;
}
`);return l}function er(n){var a=n.shapes,t=n.layers,e=n.shapeGlobalIds,r=Zt(a),i=Je(a).map(function(p){return"uniform ".concat(p.type," ").concat(p.name,";")}).join(`
`),o=function(v){return yt(v,"nodeUV","1.0")},s;if(a.length===1)s="float nodeSdfNormalized = ".concat(o(a[0]),";");else{var l=a.map(function(p,v){var f=e?e[v]:v;return"    case ".concat(f,": nodeSdfNormalized = ").concat(o(p),"; break;")}).join(`
`),u=o(a[0]);s=`float nodeSdfNormalized;
  int shapeId = int(v_shapeId);
  switch (shapeId) {
`.concat(l,`
    default: nodeSdfNormalized = `).concat(u,`;
  }`)}var d=`float effectiveRadius = max(enlargedRadius - cornerRadius, 0.01);
  float ca = u_cameraAngle * v_nodeRotation;
  float ca_c = cos(ca);
  float ca_s = sin(ca);
  vec2 rotatedScreenUV = mat2(ca_c, -ca_s, ca_s, ca_c) * screenUV;
  vec2 nodeUV = vec2(rotatedScreenUV.x, -rotatedScreenUV.y) / effectiveRadius;`,c=`#version 300 es
precision highp float;

in vec2 v_uv;
in vec2 v_nodeCenter;
in float v_nodeRadius;
in vec2 v_labelCenter;
in vec2 v_labelHalfSize;
in float v_aaWidth;
in float v_shapeId;
in float v_nodeRotation;
in float v_labelAngle;
in vec4 v_backdropColor;
in vec4 v_backdropShadowColor;
in float v_backdropShadowBlur;
in float v_backdropPadding;
in vec4 v_backdropBorderColor;
in float v_backdropBorderWidth;
in float v_backdropCornerRadius;
in float v_backdropArea;
`.concat(Bi(a,t,"in"),`

uniform float u_cameraAngle;
`).concat(i,`

layout(location = 0) out vec4 fragColor;
layout(location = 1) out vec4 fragPicking;

`).concat(r,`
`).concat(Ua,`
`).concat(Ha,`
`).concat(Va,`
`).concat(Xa,`

void main() {
  vec4 backdropColor = v_backdropColor;
  vec4 shadowColor = v_backdropShadowColor;
  float shadowBlur = v_backdropShadowBlur;
  float padding = v_backdropPadding;
  vec4 borderColor = v_backdropBorderColor;
  float borderWidth = v_backdropBorderWidth;
  float cornerRadius = v_backdropCornerRadius;

  float enlargedRadius = v_nodeRadius + padding;
  vec2 screenUV = v_uv - v_nodeCenter;
  `).concat(d,`

  // Query the correct shape SDF based on shapeId
  `).concat(s,`
  float nodeSdfPixels = nodeSdfNormalized * effectiveRadius - cornerRadius;

  // Label SDF with optional corner radius and rotation
  float labelSdfPixels;
  if (v_labelHalfSize.x > 0.0) {
    vec2 labelP = v_uv - v_labelCenter;
    labelSdfPixels = sdfRoundedRotatedBox(labelP, v_labelHalfSize, v_labelAngle, cornerRadius);
  } else {
    labelSdfPixels = 10000.0;
  }

  // Select area: 0=both, 1=node, 2=label
  float combinedSdf;
  if (v_backdropArea > 1.5) {
    combinedSdf = labelSdfPixels;
  } else if (v_backdropArea > 0.5) {
    combinedSdf = nodeSdfPixels;
  } else {
    combinedSdf = min(nodeSdfPixels, labelSdfPixels);
  }

  // Fill + border composite
  float outerEdge = smoothstep(v_aaWidth, -v_aaWidth, combinedSdf);
  vec4 background;
  if (borderWidth > 0.5) {
    float innerEdge = smoothstep(v_aaWidth, -v_aaWidth, combinedSdf + borderWidth);
    float fillAlpha = innerEdge * backdropColor.a;
    vec4 fill = vec4(backdropColor.rgb * fillAlpha, fillAlpha);
    float borderAlpha = (outerEdge - innerEdge) * borderColor.a;
    vec4 border = vec4(borderColor.rgb * borderAlpha, borderAlpha);
    background = fill + border * (1.0 - fill.a);
  } else {
    float fillAlpha = outerEdge * backdropColor.a;
    background = vec4(backdropColor.rgb * fillAlpha, fillAlpha);
  }

  // Gaussian-like shadow falloff (mimics canvas shadowBlur)
  vec4 shadow = vec4(0.0);
  float sigma = shadowBlur / 2.5;
  if (sigma > 0.001) {
    float shadowDist = max(0.0, combinedSdf);
    float shadowAlpha = exp(-(shadowDist * shadowDist) / (2.0 * sigma * sigma)) * shadowColor.a;
    shadow = vec4(shadowColor.rgb * shadowAlpha, shadowAlpha);
  }

  fragColor = background + shadow * (1.0 - background.a);
  fragPicking = vec4(0.0);
}
`);return c}function tr(n){var a=["u_matrix","u_sizeRatio","u_correctionRatio","u_cameraAngle","u_resolution","u_pixelRatio","u_labelMargin","u_zoomLabelSizeRatio","u_labelPixelSnapping","u_nodeDataTexture","u_nodeDataTextureWidth","u_nodeFrameTexture","u_nodeFrameTextureWidth","u_layerAttributeTexture","u_layerAttributeTextureWidth","u_layerAttributeTexelsPerNode"],t=G(Je(n)),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;a.includes(r.name)||a.push(r.name)}}catch(i){t.e(i)}finally{t.f()}return a}function nr(n){return{vertexShader:Ja(n),fragmentShader:er(n),uniforms:tr(n.shapes)}}function ar(n,a,t,e){var r,i,o=e.label,s=o===void 0?{}:o,l=e.shapes,u=e.layers,d=e.getAttributeTexture,c=e.shapeGlobalIds;if(l.length===0)throw new Error("createBackdropProgram: at least one shape must be provided in 'shapes'");var p=(r=s.margin)!==null&&r!==void 0?r:5,v=(i=s.zoomToLabelSizeRatioFunction)!==null&&i!==void 0?i:function(){return 1},f={shapes:l,layers:u,shapeGlobalIds:c},b=nr(f),g=(function(h){function m(){var x;X(this,m);for(var y=arguments.length,_=new Array(y),T=0;T<y;T++)_[T]=arguments[T];return x=Q(this,m,[].concat(_)),S(x,"totalBackdropCount",0),S(x,"bufferCapacity",0),x}return J(m,h),j(m,[{key:"getDefinition",value:function(){var y=WebGL2RenderingContext,_=y.FLOAT,T=y.TRIANGLE_STRIP;return{VERTICES:4,VERTEX_SHADER_SOURCE:b.vertexShader,FRAGMENT_SHADER_SOURCE:b.fragmentShader,METHOD:T,UNIFORMS:b.uniforms,ATTRIBUTES:[{name:"a_nodeIndex",size:1,type:_},{name:"a_labelWidth",size:1,type:_},{name:"a_labelHeight",size:1,type:_},{name:"a_textHeight",size:1,type:_},{name:"a_positionMode",size:1,type:_},{name:"a_labelAngle",size:1,type:_},{name:"a_backdropColor",size:4,type:_},{name:"a_backdropShadowColor",size:4,type:_},{name:"a_backdropShadowBlur",size:1,type:_},{name:"a_backdropPadding",size:1,type:_},{name:"a_backdropBorderColor",size:4,type:_},{name:"a_backdropExtra",size:4,type:_},{name:"a_labelBoxOffset",size:2,type:_}],CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:_}],CONSTANT_DATA:[[-1,-1],[1,-1],[-1,1],[1,1]]}}},{key:"processBackdrop",value:function(y,_){var T=this.floats,R=this.STRIDE,E=y*R;T[E++]=_.nodeIndex,T[E++]=_.labelWidth,T[E++]=_.labelHeight,T[E++]=_.textHeight,T[E++]=Oe[_.position],T[E++]=_.labelAngle,T[E++]=_.backdropColor[0],T[E++]=_.backdropColor[1],T[E++]=_.backdropColor[2],T[E++]=_.backdropColor[3],T[E++]=_.backdropShadowColor[0],T[E++]=_.backdropShadowColor[1],T[E++]=_.backdropShadowColor[2],T[E++]=_.backdropShadowColor[3],T[E++]=_.backdropShadowBlur,T[E++]=_.backdropPadding,T[E++]=_.backdropBorderColor[0],T[E++]=_.backdropBorderColor[1],T[E++]=_.backdropBorderColor[2],T[E++]=_.backdropBorderColor[3],T[E++]=_.backdropBorderWidth,T[E++]=_.backdropCornerRadius,T[E++]=_.backdropLabelPadding,T[E++]=_.backdropArea,T[E++]=_.labelBoxOffset[0],T[E++]=_.labelBoxOffset[1]}},{key:"setUniforms",value:function(y,_){var T=_.gl,R=_.uniformLocations;T.uniformMatrix3fv(R.u_matrix,!1,y.matrix),T.uniform1f(R.u_sizeRatio,y.sizeRatio),T.uniform1f(R.u_correctionRatio,y.correctionRatio),T.uniform1f(R.u_cameraAngle,y.cameraAngle),T.uniform2f(R.u_resolution,y.width*y.pixelRatio,y.height*y.pixelRatio),T.uniform1f(R.u_pixelRatio,y.pixelRatio),T.uniform1f(R.u_labelMargin,m.labelMargin),T.uniform1f(R.u_zoomLabelSizeRatio,1/v(y.zoomRatio)),T.uniform1f(R.u_labelPixelSnapping,y.labelPixelSnapping),T.uniform1i(R.u_nodeDataTexture,y.nodeDataTextureUnit),T.uniform1i(R.u_nodeDataTextureWidth,y.nodeDataTextureWidth),T.uniform1i(R.u_nodeFrameTexture,y.nodeFrameTextureUnit),T.uniform1i(R.u_nodeFrameTextureWidth,y.nodeFrameTextureWidth);var E=d();R.u_layerAttributeTexture&&E&&(E.bind(Me),T.uniform1i(R.u_layerAttributeTexture,Me),T.uniform1i(R.u_layerAttributeTextureWidth,E.getTextureWidth()),T.uniform1i(R.u_layerAttributeTexelsPerNode,E.getTexelsPerItem()));var D=G(Je(l)),P;try{for(D.s();!(P=D.n()).done;){var w=P.value;this.setTypedUniform(w,_)}}catch(A){D.e(A)}finally{D.f()}}},{key:"hasNothingToRender",value:function(){return this.totalBackdropCount===0}},{key:"drawWebGL",value:function(y,_){var T=_.gl;this.totalBackdropCount!==0&&(this.isInstanced?T.drawArraysInstanced(y,0,this.VERTICES,this.totalBackdropCount):T.drawArrays(y,0,this.totalBackdropCount*this.VERTICES))}},{key:"reallocate",value:function(y){this.totalBackdropCount=y,y>this.bufferCapacity&&(this.bufferCapacity=Math.max(y,Math.ceil(this.bufferCapacity*1.5)||10),te(m,"reallocate",this,3)([this.bufferCapacity]))}}])})(Pe);return S(g,"labelMargin",p),new g(n,a,t)}var jn=(function(n){function a(){var t;X(this,a);for(var e=arguments.length,r=new Array(e),i=0;i<e;i++)r[i]=arguments[i];return t=Q(this,a,[].concat(r)),S(t,"totalCharacterCount",0),S(t,"bufferCapacity",0),t}return J(a,n),j(a,[{key:"processLabel",value:function(e,r,i){if(i.hidden||!i.text)return 0;for(var o=i.text,s=o.length,l=0;l<s;l++){var u=o[l];this.processCharacter(r+l,i,u,l)}return s}},{key:"hasNothingToRender",value:function(){return this.totalCharacterCount===0}},{key:"drawWebGL",value:function(e,r){var i=r.gl;this.totalCharacterCount!==0&&(this.isInstanced?i.drawArraysInstanced(e,0,this.VERTICES,this.totalCharacterCount):i.drawArrays(e,0,this.totalCharacterCount*this.VERTICES))}},{key:"reallocate",value:function(e){this.totalCharacterCount=e,e>this.bufferCapacity&&(this.bufferCapacity=Math.max(e,Math.ceil(this.bufferCapacity*1.5)||1e3),te(a,"reallocate",this,3)([this.bufferCapacity]))}}])})(Pe);function Vs(){var n=`#version 300 es

in float a_nodeIndex;
in vec4 a_id;
in vec4 a_color;
in float a_labelWidth;
in float a_labelHeight;
in float a_textHeight;
in float a_positionMode;
in float a_labelAngle;
in float a_padding;
in vec2 a_quadCorner;

uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
uniform vec2 u_resolution;
uniform float u_pixelRatio;
uniform float u_labelMargin;
uniform float u_zoomLabelSizeRatio;
uniform float u_labelPixelSnapping;
uniform float u_pickingPadding;
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_nodeFrameTexture;
uniform int u_nodeFrameTextureWidth;

out vec4 v_id;
out vec4 v_color;

`.concat(me,`
`).concat(Le,`
`).concat(Ue,`
`).concat(Wn,`

void main() {
  int nodeIdx = int(a_nodeIndex);

  // Node data: (x, y, size, shapeId).
  vec4 nodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  vec2 nodePosition = nodeData.xy;
  float nodeSize = nodeData.z;

  // Shape-aware edge distance, read once from the shared frame texture.
  float edgeDist = readFrameTexel(u_nodeFrameTexture, u_nodeFrameTextureWidth, nodeIdx).r;

  // Per-node label rotation alignment: 0 = viewport, 1 = label turns with camera.
  float labelRotation = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx).g;

  `).concat(On,`

  float zoomScale = u_zoomLabelSizeRatio;
  float labelW = a_labelWidth * zoomScale * u_pixelRatio;
  float labelH = a_labelHeight * zoomScale * u_pixelRatio;
  float labelMargin = u_labelMargin * zoomScale * u_pixelRatio;
#ifdef PICKING_MODE
  float padding = u_pickingPadding * u_pixelRatio;
#else
  float padding = a_padding * u_pixelRatio;
#endif

  if (labelW <= 0.0) {
    gl_Position = vec4(2.0, 0.0, 0.0, 1.0);
    v_id = vec4(0.0);
    v_color = vec4(0.0);
    return;
  }

  vec2 labelHalfSize = vec2(labelW * 0.5 + padding, labelH * 0.5 + padding);
  vec2 labelOffset = vec2(0.0);

  // Graph-aligned labels add the camera angle so the rect orbits with the text.
  float labelAngle = a_labelAngle - labelRotation * u_cameraAngle;
  float la_c = cos(labelAngle);
  float la_s = sin(labelAngle);
  mat2 labelRotMat = mat2(la_c, -la_s, la_s, la_c);

  vec3 nodeClip = u_matrix * vec3(nodePosition, 1.0);
  vec2 nodeScreen = vec2(
    (nodeClip.x + 1.0) * u_resolution.x,
    (1.0 - nodeClip.y) * u_resolution.y
  ) * 0.5;
  vec2 snapDelta = (round(nodeScreen) - nodeScreen) * u_labelPixelSnapping;

  if (a_positionMode < 4.0) {
    float labelStart = nodeRadiusPixels * edgeDist + labelMargin;
    float textHalf = a_textHeight * zoomScale * u_pixelRatio * 0.5;
    // Box center uses the text half-size; the padding expands the quad below.
    labelOffset = labelRotMat * labelBoxCenter(a_positionMode, labelStart, vec2(labelW * 0.5, labelH * 0.5), textHalf);
  }

  // Rotate the rect with the label so it stays aligned with the (rotated) text.
  vec2 localPos = labelOffset + labelRotMat * (a_quadCorner * labelHalfSize);
  vec2 ndcOffset = (localPos + snapDelta) * 2.0 / u_resolution;
  ndcOffset.y = -ndcOffset.y;

  gl_Position = vec4(nodeClip.xy + ndcOffset, 0.0, 1.0);
  v_id = a_id;
  v_color = a_color;
}
`);return n}var Xs=`#version 300 es
precision highp float;

in vec4 v_id;
in vec4 v_color;

out vec4 fragColor;

void main() {
  #ifdef PICKING_MODE
    fragColor = v_id;
  #else
    if (v_color.a <= 0.0) discard;
    // v_color is non-premultiplied RGBA (0-1); convert to premultiplied for blending
    fragColor = vec4(v_color.rgb * v_color.a, v_color.a);
  #endif
}
`;function js(n,a,t,e){var r,i,o=e.label,s=o===void 0?{}:o,l=(r=s.margin)!==null&&r!==void 0?r:Be,u=(i=s.zoomToLabelSizeRatioFunction)!==null&&i!==void 0?i:function(){return 1},d=Vs(),c=(function(p){function v(){var f;X(this,v);for(var b=arguments.length,g=new Array(b),h=0;h<b;h++)g[h]=arguments[h];return f=Q(this,v,[].concat(g)),S(f,"totalCount",0),S(f,"bufferCapacity",0),f}return J(v,p),j(v,[{key:"getDefinition",value:function(){var b=WebGL2RenderingContext,g=b.FLOAT,h=b.UNSIGNED_BYTE,m=b.TRIANGLE_STRIP;return{VERTICES:4,VERTEX_SHADER_SOURCE:d,FRAGMENT_SHADER_SOURCE:Xs,METHOD:m,UNIFORMS:["u_matrix","u_sizeRatio","u_correctionRatio","u_cameraAngle","u_resolution","u_pixelRatio","u_labelMargin","u_zoomLabelSizeRatio","u_labelPixelSnapping","u_pickingPadding","u_nodeDataTexture","u_nodeDataTextureWidth","u_nodeFrameTexture","u_nodeFrameTextureWidth"],ATTRIBUTES:[{name:"a_nodeIndex",size:1,type:g},{name:"a_id",size:4,type:h,normalized:!0},{name:"a_color",size:4,type:h,normalized:!0},{name:"a_labelWidth",size:1,type:g},{name:"a_labelHeight",size:1,type:g},{name:"a_textHeight",size:1,type:g},{name:"a_positionMode",size:1,type:g},{name:"a_labelAngle",size:1,type:g},{name:"a_padding",size:1,type:g}],CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:g}],CONSTANT_DATA:[[-1,-1],[1,-1],[-1,1],[1,1]]}}},{key:"processLabelBackground",value:function(b,g){var h=this.floats,m=this.ints,x=b*this.STRIDE;h[x++]=g.nodeIndex,m[x++]=g.id,h[x++]=g.color,h[x++]=g.labelWidth,h[x++]=g.labelHeight,h[x++]=g.textHeight,h[x++]=g.positionMode,h[x++]=g.labelAngle,h[x++]=g.padding}},{key:"setUniforms",value:function(b,g){var h=g.gl,m=g.uniformLocations;h.uniformMatrix3fv(m.u_matrix,!1,b.matrix),h.uniform1f(m.u_sizeRatio,b.sizeRatio),h.uniform1f(m.u_correctionRatio,b.correctionRatio),h.uniform1f(m.u_cameraAngle,b.cameraAngle),h.uniform2f(m.u_resolution,b.width*b.pixelRatio,b.height*b.pixelRatio),h.uniform1f(m.u_pixelRatio,b.pixelRatio),h.uniform1f(m.u_labelMargin,v.labelMargin),h.uniform1f(m.u_zoomLabelSizeRatio,1/u(b.zoomRatio)),h.uniform1f(m.u_labelPixelSnapping,b.labelPixelSnapping),h.uniform1f(m.u_pickingPadding,b.labelPickingPadding),h.uniform1i(m.u_nodeDataTexture,b.nodeDataTextureUnit),h.uniform1i(m.u_nodeDataTextureWidth,b.nodeDataTextureWidth),h.uniform1i(m.u_nodeFrameTexture,b.nodeFrameTextureUnit),h.uniform1i(m.u_nodeFrameTextureWidth,b.nodeFrameTextureWidth)}},{key:"hasNothingToRender",value:function(){return this.totalCount===0}},{key:"drawWebGL",value:function(b,g){var h=g.gl;this.totalCount!==0&&h.drawArraysInstanced(h.TRIANGLE_STRIP,0,this.VERTICES,this.totalCount)}},{key:"reallocate",value:function(b){this.totalCount=b,b>this.bufferCapacity&&(this.bufferCapacity=Math.max(b,Math.ceil(this.bufferCapacity*1.5)||10),te(v,"reallocate",this,3)([this.bufferCapacity]))}}])})(Pe);return S(c,"labelMargin",l),new c(n,a,t)}var _e={fontSize:64,buffer:8,radius:24,cutoff:.25,maxTextureSize:2048,debounceTimeout:100},Ut=2,Xt=1e20;function qs(n,a,t,e,r){var i=n+r*4,o=document.createElement("canvas");o.width=i,o.height=i;var s=o.getContext("2d",{willReadFrequently:!0});return s.font="".concat(e," ").concat(t," ").concat(n,"px ").concat(a),s.textBaseline="alphabetic",s.textAlign="left",s.fillStyle="black",{ctx:s,canvasSize:i,gridOuter:new Float64Array(i*i),gridInner:new Float64Array(i*i),f:new Float64Array(i),z:new Float64Array(i+1),v:new Uint16Array(i)}}function Ys(n,a,t,e,r){var i=n.ctx,o=n.canvasSize,s=i.measureText(a),l=s.width,u=s.actualBoundingBoxAscent,d=s.actualBoundingBoxDescent,c=s.actualBoundingBoxLeft,p=s.actualBoundingBoxRight,v=Math.ceil(u),f=Math.ceil(c),b=Math.max(0,Math.min(o-t,Math.ceil(c)+Math.ceil(p))),g=Math.min(o-t,v+Math.ceil(d)),h=b+2*t,m=g+2*t,x=Math.max(h*m,0),y=new Uint8ClampedArray(x),_={data:y,width:h,height:m,glyphWidth:b,glyphHeight:g,glyphTop:v,glyphLeft:f,glyphAdvance:l};if(b===0||g===0)return _;var T=n.gridInner,R=n.gridOuter;i.clearRect(t,t,b,g),i.fillText(a,t+f,t+v);var E=i.getImageData(t,t,b,g);R.fill(Xt,0,x),T.fill(0,0,x);for(var D=0;D<g;D++)for(var P=0;P<b;P++){var w=E.data[4*(D*b+P)+3]/255;if(w!==0){var A=(D+t)*h+P+t;if(w===1)R[A]=0,T[A]=Xt;else{var F=.5-w;R[A]=F>0?F*F:0,T[A]=F<0?F*F:0}}}Ei(R,0,0,h,m,h,n.f,n.v,n.z),Ei(T,t,t,b,g,h,n.f,n.v,n.z);for(var L=0;L<x;L++){var k=Math.sqrt(R[L])-Math.sqrt(T[L]);y[L]=Math.round(255-255*(k/e+r))}return _}function Ei(n,a,t,e,r,i,o,s,l){for(var u=a;u<a+e;u++)Ri(n,t*i+u,i,r,o,s,l);for(var d=t;d<t+r;d++)Ri(n,d*i+a,1,e,o,s,l)}function Ri(n,a,t,e,r,i,o){i[0]=0,o[0]=-Xt,o[1]=Xt,r[0]=n[a];for(var s=1,l=0,u=0;s<e;s++){r[s]=n[a+s*t];var d=s*s;do{var c=i[l];u=(r[s]-r[c]+d-c*c)/(s-c)/2}while(u<=o[l]&&--l>-1);l++,i[l]=s,o[l]=u,o[l+1]=Xt}for(var p=0,v=0;p<e;p++){for(;o[v+1]<p;)v++;var f=i[v],b=p-f;n[a+p*t]=r[f]+b*b}}var Ce=(function(n){function a(){var t,e=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};return X(this,a),t=Q(this,a),S(t,"fonts",new Map),S(t,"textures",[]),S(t,"cursor",{x:0,y:0,rowHeight:0,atlasIndex:0}),S(t,"pendingGlyphs",[]),S(t,"debounceTimer",null),t.options=O(O({},_e),e),t.canvas=document.createElement("canvas"),t.canvas.width=t.options.maxTextureSize,t.canvas.height=t.options.maxTextureSize,t.ctx=t.canvas.getContext("2d",{willReadFrequently:!0}),t.measureCanvas=document.createElement("canvas"),t.measureCtx=t.measureCanvas.getContext("2d"),t.textures.push(t.ctx.getImageData(0,0,1,1)),t}return J(a,n),j(a,[{key:"getFontKey",value:function(e){return"".concat(e.family,"-").concat(e.weight,"-").concat(e.style)}},{key:"registerFont",value:function(e){var r=this.getFontKey(e);if(this.fonts.has(r))return r;var i=qs(this.options.fontSize,e.family,e.weight,e.style,this.options.buffer);return this.fonts.set(r,{descriptor:e,generator:i,glyphs:new Map}),r}},{key:"ensureGlyphs",value:function(e,r){var i=this.fonts.get(r);if(!i)throw new Error('Font "'.concat(r,'" is not registered. Call registerFont() first.'));var o=!1,s=G(e),l;try{for(s.s();!(l=s.n()).done;){var u=l.value,d=u.codePointAt(0);d!==void 0&&(i.glyphs.has(d)||(this.pendingGlyphs.push({fontKey:r,charCode:d}),o=!0))}}catch(c){s.e(c)}finally{s.f()}o&&this.scheduleTextureGeneration()}},{key:"measureText",value:function(e,r){var i=this.fonts.get(r);if(!i)throw new Error('Font "'.concat(r,'" is not registered.'));var o=i.descriptor,s=o.family,l=o.weight,u=o.style;return this.measureCtx.font="".concat(u," ").concat(l," ").concat(this.options.fontSize,"px ").concat(s),this.measureCtx.measureText(e).width}},{key:"getGlyph",value:function(e,r){var i=this.fonts.get(r);if(i)return i.glyphs.get(e)}},{key:"getTextures",value:function(){return this.textures}},{key:"getFontCount",value:function(){return this.fonts.size}},{key:"getGlyphCount",value:function(){var e=0,r=G(this.fonts.values()),i;try{for(r.s();!(i=r.n()).done;){var o=i.value;e+=o.glyphs.size}}catch(s){r.e(s)}finally{r.f()}return e}},{key:"hasPendingGlyphs",value:function(){return this.pendingGlyphs.length>0}},{key:"flush",value:function(){this.debounceTimer&&(clearTimeout(this.debounceTimer),this.debounceTimer=null),this.generateTextures()}},{key:"destroy",value:function(){this.debounceTimer&&clearTimeout(this.debounceTimer),this.fonts.clear(),this.textures=[],this.pendingGlyphs=[],this.removeAllListeners()}},{key:"scheduleTextureGeneration",value:function(){var e=this;this.debounceTimer===null&&(this.options.debounceTimeout===null?this.generateTextures():this.debounceTimer=setTimeout(function(){e.debounceTimer=null,e.generateTextures()},this.options.debounceTimeout))}},{key:"generateTextures",value:function(){if(this.pendingGlyphs.length!==0){var e=this.options,r=e.maxTextureSize,i=e.buffer,o=e.radius,s=e.cutoff,l=G(this.pendingGlyphs),u;try{for(l.s();!(u=l.n()).done;){var d=u.value,c=d.fontKey,p=d.charCode,v=this.fonts.get(c);if(!(!v||v.glyphs.has(p))){var f=String.fromCodePoint(p),b=Ys(v.generator,f,i,o,s),g=b.width,h=b.height;this.cursor.x+g+Ut>r&&(this.cursor.x=0,this.cursor.y+=this.cursor.rowHeight+Ut,this.cursor.rowHeight=0),this.cursor.y+h+Ut>r&&(this.finalizeCurrentTexture(),this.cursor={x:0,y:0,rowHeight:0,atlasIndex:this.cursor.atlasIndex+1},this.ctx.clearRect(0,0,r,r));for(var m=b.data,x=new Uint8ClampedArray(g*h*4),y=0;y<m.length;y++){var _=y*4;x[_]=255,x[_+1]=255,x[_+2]=255,x[_+3]=m[y]}var T=new ImageData(x,g,h);this.ctx.putImageData(T,this.cursor.x,this.cursor.y);var R={charCode:p,width:b.glyphWidth,height:b.glyphHeight,bearingX:-b.glyphLeft-i,bearingY:b.glyphTop+i,advance:b.glyphAdvance,atlasX:this.cursor.x,atlasY:this.cursor.y,atlasWidth:g,atlasHeight:h,atlasIndex:this.cursor.atlasIndex};v.glyphs.set(p,R),this.cursor.x+=g+Ut,this.cursor.rowHeight=Math.max(this.cursor.rowHeight,h)}}}catch(E){l.e(E)}finally{l.f()}this.finalizeCurrentTexture(),this.pendingGlyphs=[],this.emit(a.ATLAS_UPDATED_EVENT,{textures:this.textures,glyphCount:this.getGlyphCount()})}}},{key:"finalizeCurrentTexture",value:function(){var e=this.options.maxTextureSize,r=this.cursor.y>0||this.cursor.rowHeight>0,i=Math.min(e,Math.max(this.cursor.x,r?e:1)),o=Math.min(e,this.cursor.y+this.cursor.rowHeight+Ut),s=this.ctx.getImageData(0,0,i,o);this.cursor.atlasIndex>=this.textures.length?this.textures.push(s):this.textures[this.cursor.atlasIndex]=s}}])})(Li.EventEmitter);S(Ce,"ATLAS_UPDATED_EVENT","atlasUpdated");var Ks=_e.fontSize;function rr(){var n=`  // -------------------------------------------------------------------------
  // Step 3: Calculate position offset from the shared edge distance
  // -------------------------------------------------------------------------
  vec2 positionOffset = vec2(0.0);

  if (a_positionMode < 4.0) {
    vec2 screenDir = getLabelDirection(a_positionMode);
    float boundaryDistPixels = nodeRadiusPixels * edgeDist;
    positionOffset = screenDir * (boundaryDistPixels + margin);
  }`,a=`#version 300 es

// ============================================================================
// Attributes
// ============================================================================

// Per-character (instanced)
in float a_nodeIndex;        // Index into node data texture
in vec2 a_charOffset;        // Character offset from label origin (pixels)
in vec2 a_charSize;          // Character dimensions (pixels)
in vec4 a_texCoords;         // Atlas coords: (x, y, width, height) in pixels
in vec4 a_color;             // Text color (RGBA)
in float a_margin;           // Gap between node edge and label (pixels)
in float a_positionMode;     // Position: 0=right, 1=left, 2=above, 3=below, 4=over
in float a_labelWidth;       // Total label width (pixels)
in float a_labelHeight;      // Label height (pixels)
in float a_verticalCenter;   // Vertical center offset from baseline (pixels)
in float a_textHeight;       // Actual text height: maxAscent + maxDescent (pixels)
in float a_labelAngle;       // Label rotation angle (radians)

// Per-vertex (constant quad corners)
in vec2 a_quadCorner;        // Quad corner: [-1,-1], [1,-1], [-1,1], [1,1]

// ============================================================================
// Uniforms
// ============================================================================

uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
uniform vec2 u_resolution;
uniform vec2 u_atlasSize;
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_nodeFrameTexture;
uniform int u_nodeFrameTextureWidth;
uniform float u_zoomLabelSizeRatio;
uniform float u_labelPixelSnapping;
uniform float u_pixelRatio;

// ============================================================================
// Varyings
// ============================================================================

out vec2 v_texCoord;
out vec4 v_color;
out float v_fontScale;

// ============================================================================
// Constants
// ============================================================================

const float bias = 255.0 / 254.0;
const float ATLAS_FONT_SIZE = `.concat(Y(Ks),`;

// ============================================================================
// Helper Functions
// ============================================================================

`).concat(me,`
`).concat(Le,`
`).concat(Ue,`
`).concat(Bn,`

// ============================================================================
// Main
// ============================================================================

void main() {
  // -------------------------------------------------------------------------
  // Step 0: Fetch node data + shared edge distance from textures
  // -------------------------------------------------------------------------
  // Node-data texture format: vec4(x, y, size, shapeId)
  // 2D texture layout: texCoord = (index % width, index / width)
  int nodeIdx = int(a_nodeIndex);
  vec4 nodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  vec2 a_anchorPosition = nodeData.xy;
  float a_nodeSize = nodeData.z;

  // Normalized edge distance from the shared frame texture (the frame-pass ran
  // the SDF search once; the label just reads the result).
  float edgeDist = readFrameTexel(u_nodeFrameTexture, u_nodeFrameTextureWidth, nodeIdx).r;

  // Per-node label rotation alignment: 0 = viewport, 1 = label turns with camera.
  float labelRotation = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx).g;

  // Apply zoom-dependent label size scaling
  // Positional values are in CSS pixels; multiply by u_pixelRatio to convert to
  // physical pixels, which is what the NDC conversion (/ u_resolution) expects.
  float zoomScale = u_zoomLabelSizeRatio;
  float margin = a_margin * zoomScale * u_pixelRatio;
  vec2 charOffset = a_charOffset * zoomScale * u_pixelRatio;
  vec2 charSize = a_charSize * zoomScale * u_pixelRatio;
  float labelWidth = a_labelWidth * zoomScale * u_pixelRatio;
  float labelHeight = a_labelHeight * zoomScale;

  // Font scale: ratio of CSS label size to the base atlas font size.
  // Divided by u_pixelRatio because the atlas is generated at ATLAS_FONT_SIZE * pixelRatio,
  // which cancels out the u_pixelRatio in the fragment shader's gamma formula and keeps
  // the anti-aliasing band width consistent across pixel densities.
  v_fontScale = a_labelHeight * zoomScale / (ATLAS_FONT_SIZE * u_pixelRatio);

  // -------------------------------------------------------------------------
  // Step 1: Transform node position to clip space
  // -------------------------------------------------------------------------
  vec3 anchorClip = u_matrix * vec3(a_anchorPosition, 1.0);

  // -------------------------------------------------------------------------
  // Step 2: Convert node size to screen pixels
  // -------------------------------------------------------------------------
  float matrixScaleX = length(vec2(u_matrix[0][0], u_matrix[1][0]));
  float nodeRadiusGraphSpace = a_nodeSize * u_correctionRatio / u_sizeRatio * 2.0;
  float nodeRadiusNDC = nodeRadiusGraphSpace * matrixScaleX;
  float nodeRadiusPixels = nodeRadiusNDC * u_resolution.x / 2.0;

`).concat(n,`

  // -------------------------------------------------------------------------
  // Step 4: Calculate final vertex position
  // -------------------------------------------------------------------------
  vec2 cornerOffset = (a_quadCorner + 1.0) * 0.5;
  vec2 charPixelPos = positionOffset + charOffset + cornerOffset * charSize;

  // Apply text alignment based on position mode
  float verticalCenter = a_verticalCenter * zoomScale * u_pixelRatio;
  float textHeight = a_textHeight * zoomScale * u_pixelRatio;
  float baselineToDescent = textHeight / 2.0 - verticalCenter;
  float baselineToAscent = textHeight / 2.0 + verticalCenter;

  if (a_positionMode < 0.5) {
    // Right: vertically center
    charPixelPos.y += verticalCenter;
  } else if (a_positionMode < 1.5) {
    // Left: right-align and vertically center
    charPixelPos.x -= labelWidth;
    charPixelPos.y += verticalCenter;
  } else if (a_positionMode < 2.5) {
    // Above: center horizontally, bottom of text at anchor
    charPixelPos.x -= labelWidth * 0.5;
    charPixelPos.y -= baselineToDescent;
  } else if (a_positionMode < 3.5) {
    // Below: center horizontally, top of text at anchor
    charPixelPos.x -= labelWidth * 0.5;
    charPixelPos.y += baselineToAscent;
  } else {
    // Over: center both
    charPixelPos.x -= labelWidth * 0.5;
    charPixelPos.y += verticalCenter;
  }

  // Apply label angle rotation. Graph-aligned labels add the camera angle so the
  // whole label orbits the node in lockstep with the frame-pass edge distance.
  float labelAngle = a_labelAngle - labelRotation * u_cameraAngle;
  float la_c = cos(labelAngle);
  float la_s = sin(labelAngle);
  mat2 labelRotMat = mat2(la_c, -la_s, la_s, la_c);
  charPixelPos = labelRotMat * charPixelPos;

  // Snap node center to pixel grid so label/backdrop/attachment move as a unit
  vec2 nodeScreen = vec2(
    (anchorClip.x + 1.0) * u_resolution.x,
    (1.0 - anchorClip.y) * u_resolution.y
  ) * 0.5;
  charPixelPos += (round(nodeScreen) - nodeScreen) * u_labelPixelSnapping;

  // Convert to NDC (flip Y: screen Y-down -> clip Y-up)
  vec2 ndcOffset = vec2(charPixelPos.x, -charPixelPos.y) * 2.0 / u_resolution;
  gl_Position = vec4(anchorClip.xy + ndcOffset, 0.0, 1.0);

  // -------------------------------------------------------------------------
  // Step 5: Texture coordinates
  // -------------------------------------------------------------------------
  v_texCoord = (a_texCoords.xy + cornerOffset * a_texCoords.zw) / u_atlasSize;

  // -------------------------------------------------------------------------
  // Step 6: Pass color
  // -------------------------------------------------------------------------
  v_color = a_color;
  v_color.a *= bias;
}
`);return a}function ir(){var n=`#version 300 es
precision highp float;

in vec2 v_texCoord;
in vec4 v_color;
in float v_fontScale;

uniform sampler2D u_atlas;
uniform float u_gamma;
uniform float u_sdfBuffer;
uniform float u_pixelRatio;

// Fragment output (single target - picking handled via separate pass)
out vec4 fragColor;

void main() {
  #ifdef PICKING_MODE
    // Labels are not pickable - discard all fragments in picking mode
    discard;
  #else
    // Sample SDF value from atlas (high = inside glyph, low = outside)
    float sdfValue = texture(u_atlas, v_texCoord).a;

    // Edge threshold: 1.0 - cutoff = 0.75 for default cutoff=0.25
    // This is where the glyph edge is located in the SDF
    float edgeThreshold = 1.0 - u_sdfBuffer;

    // Gamma controls the anti-aliasing band width.
    // Scale inversely with font scale so small labels get a wider AA band
    // (smoother) and large labels get a tighter band (sharper).
    float gamma = u_gamma / (u_pixelRatio * v_fontScale);

    // Pure gamma-based anti-aliasing using smoothstep
    // The AA band extends from (threshold - gamma) to (threshold + gamma)
    float alpha = smoothstep(edgeThreshold - gamma, edgeThreshold + gamma, sdfValue);

    // Premultiplied alpha output for correct blending
    float finalAlpha = v_color.a * alpha;
    fragColor = vec4(v_color.rgb * finalAlpha, finalAlpha);
  #endif
}
`;return n}function or(){return["u_matrix","u_sizeRatio","u_correctionRatio","u_cameraAngle","u_resolution","u_atlasSize","u_atlas","u_gamma","u_sdfBuffer","u_pixelRatio","u_nodeDataTexture","u_nodeDataTextureWidth","u_nodeFrameTexture","u_nodeFrameTextureWidth","u_zoomLabelSizeRatio","u_labelPixelSnapping"]}function sr(){return{vertexShader:rr(),fragmentShader:ir(),uniforms:or()}}function lr(n,a,t,e){var r,i,o=e.label,s=o===void 0?{}:o,l=(r=s.margin)!==null&&r!==void 0?r:Be,u=(i=s.zoomToLabelSizeRatioFunction)!==null&&i!==void 0?i:function(){return 1},d=sr(),c=(function(p){function v(f,b,g){var h,m,x,y;if(X(this,v),y=Q(this,v,[f,b,g]),S(y,"atlasTexture",null),S(y,"atlasNeedsUpdate",!1),S(y,"labelGlyphCache",new Map),y.atlasFontSize=_e.fontSize*$e(),y.atlasManager=new Ce({fontSize:y.atlasFontSize}),y.gamma=.025,y.sdfBuffer=_e.cutoff,y.atlasTexture=f.createTexture(),!y.atlasTexture)throw new Error("NodeLabelProgram: failed to create atlas texture");f.bindTexture(f.TEXTURE_2D,y.atlasTexture),f.texParameteri(f.TEXTURE_2D,f.TEXTURE_WRAP_S,f.CLAMP_TO_EDGE),f.texParameteri(f.TEXTURE_2D,f.TEXTURE_WRAP_T,f.CLAMP_TO_EDGE),f.texParameteri(f.TEXTURE_2D,f.TEXTURE_MIN_FILTER,f.LINEAR),f.texParameteri(f.TEXTURE_2D,f.TEXTURE_MAG_FILTER,f.LINEAR),f.bindTexture(f.TEXTURE_2D,null),y.atlasManager.on(Ce.ATLAS_UPDATED_EVENT,function(){y.atlasNeedsUpdate=!0});var _={family:((h=s.font)===null||h===void 0?void 0:h.family)||"sans-serif",weight:((m=s.font)===null||m===void 0?void 0:m.weight)||"normal",style:((x=s.font)===null||x===void 0?void 0:x.style)||"normal"};return y.defaultFontKey=y.atlasManager.registerFont(_),y}return J(v,p),j(v,[{key:"getDefinition",value:function(){var b=WebGL2RenderingContext,g=b.FLOAT,h=b.UNSIGNED_BYTE,m=b.TRIANGLE_STRIP;return{VERTICES:4,VERTEX_SHADER_SOURCE:d.vertexShader,FRAGMENT_SHADER_SOURCE:d.fragmentShader,METHOD:m,UNIFORMS:d.uniforms,ATTRIBUTES:[{name:"a_nodeIndex",size:1,type:g},{name:"a_charOffset",size:2,type:g},{name:"a_charSize",size:2,type:g},{name:"a_texCoords",size:4,type:g},{name:"a_color",size:4,type:h,normalized:!0},{name:"a_margin",size:1,type:g},{name:"a_positionMode",size:1,type:g},{name:"a_labelWidth",size:1,type:g},{name:"a_labelHeight",size:1,type:g},{name:"a_verticalCenter",size:1,type:g},{name:"a_textHeight",size:1,type:g},{name:"a_labelAngle",size:1,type:g}],CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:g}],CONSTANT_DATA:[[-1,-1],[1,-1],[-1,1],[1,1]]}}},{key:"prepareLabelGlyphs",value:function(b,g){if(g.hidden||!g.text){this.labelGlyphCache.delete(b);return}var h=g.text,m=g.fontKey||this.defaultFontKey;this.atlasManager.ensureGlyphs(h,m);var x=[],y=[],_=0,T=0,R=0,E=G(h),D;try{for(E.s();!(D=E.n()).done;){var P=D.value,w=P.codePointAt(0);if(w===void 0){x.push(void 0),y.push(_);continue}var A=this.atlasManager.getGlyph(w,m);x.push(A),y.push(_),A&&(_+=A.advance,T=Math.max(T,A.bearingY),R=Math.max(R,A.atlasHeight-A.bearingY))}}catch(F){E.e(F)}finally{E.f()}this.labelGlyphCache.set(b,{glyphs:x,xOffsets:y,totalWidth:_,totalHeight:T+R,verticalCenterOffset:(T-R)/2})}},{key:"processCharacter",value:function(b,g,h,m){var x=this.floats,y=this.STRIDE,_=b*y,T=this.labelGlyphCache.get(g.parentKey);if(!T||!T.glyphs[m]){for(var R=0;R<y;R++)x[_+R]=0;return}var E=T.glyphs[m],D=T.xOffsets[m],P=g.size/this.atlasFontSize,w=ie(g.color),A=_;x[A++]=g.nodeIndex,x[A++]=(D+E.bearingX)*P,x[A++]=-E.bearingY*P,x[A++]=E.atlasWidth*P,x[A++]=E.atlasHeight*P,x[A++]=E.atlasX,x[A++]=E.atlasY,x[A++]=E.atlasWidth,x[A++]=E.atlasHeight,x[A++]=w,x[A++]=g.margin,x[A++]=Oe[g.position],x[A++]=T.totalWidth*P,x[A++]=g.size,x[A++]=T.verticalCenterOffset*P,x[A++]=T.totalHeight*P,x[A++]=g.labelAngle}},{key:"processLabel",value:function(b,g,h){return this.prepareLabelGlyphs(b,h),te(v,"processLabel",this,3)([b,g,h])}},{key:"updateAtlasTexture",value:function(){if(this.atlasNeedsUpdate){var b=this.normalProgram.gl,g=this.atlasManager.getTextures();if(g.length!==0){var h=g[0];b.bindTexture(b.TEXTURE_2D,this.atlasTexture),b.texImage2D(b.TEXTURE_2D,0,b.RGBA,h.width,h.height,0,b.RGBA,b.UNSIGNED_BYTE,h.data),b.bindTexture(b.TEXTURE_2D,null),this.atlasNeedsUpdate=!1}}}},{key:"setUniforms",value:function(b,g){var h=g.gl,m=g.uniformLocations;h.uniformMatrix3fv(m.u_matrix,!1,b.matrix),h.uniform1f(m.u_sizeRatio,b.sizeRatio),h.uniform1f(m.u_correctionRatio,b.correctionRatio),h.uniform1f(m.u_cameraAngle,b.cameraAngle),h.uniform2f(m.u_resolution,b.width*b.pixelRatio,b.height*b.pixelRatio);var x=this.atlasManager.getTextures();x.length>0?h.uniform2f(m.u_atlasSize,x[0].width,x[0].height):h.uniform2f(m.u_atlasSize,1,1),h.activeTexture(h.TEXTURE0),h.bindTexture(h.TEXTURE_2D,this.atlasTexture),h.uniform1i(m.u_atlas,0),m.u_nodeDataTexture!==void 0&&h.uniform1i(m.u_nodeDataTexture,b.nodeDataTextureUnit),m.u_nodeDataTextureWidth!==void 0&&h.uniform1i(m.u_nodeDataTextureWidth,b.nodeDataTextureWidth),h.uniform1i(m.u_nodeFrameTexture,b.nodeFrameTextureUnit),h.uniform1i(m.u_nodeFrameTextureWidth,b.nodeFrameTextureWidth),h.uniform1f(m.u_gamma,this.gamma),h.uniform1f(m.u_sdfBuffer,this.sdfBuffer),h.uniform1f(m.u_pixelRatio,b.pixelRatio),h.uniform1f(m.u_zoomLabelSizeRatio,1/v.zoomToLabelSizeRatioFunction(b.zoomRatio)),h.uniform1f(m.u_labelPixelSnapping,b.labelPixelSnapping)}},{key:"renderProgram",value:function(b,g){this.updateAtlasTexture(),this.atlasManager.hasPendingGlyphs()&&(this.atlasManager.flush(),this.updateAtlasTexture()),te(v,"renderProgram",this,3)([b,g])}},{key:"registerFont",value:function(b){var g=arguments.length>1&&arguments[1]!==void 0?arguments[1]:"normal",h=arguments.length>2&&arguments[2]!==void 0?arguments[2]:"normal";return this.atlasManager.registerFont({family:b,weight:g,style:h})}},{key:"getAtlasManager",value:function(){return this.atlasManager}},{key:"measureLabel",value:function(b,g,h){var m=h||this.defaultFontKey;this.atlasManager.ensureGlyphs(b,m),this.atlasManager.hasPendingGlyphs()&&this.atlasManager.flush();var x=0,y=0,_=0,T=G(b),R;try{for(T.s();!(R=T.n()).done;){var E=R.value,D=E.codePointAt(0);if(D!==void 0){var P=this.atlasManager.getGlyph(D,m);P&&(x+=P.advance,y=Math.max(y,P.bearingY),_=Math.max(_,P.atlasHeight-P.bearingY))}}}catch(A){T.e(A)}finally{T.f()}var w=g/this.atlasFontSize;return{width:x*w,height:g,textHeight:(y+_)*w}}},{key:"ensureGlyphsReady",value:function(b,g){var h=g||this.defaultFontKey,m=G(b),x;try{for(m.s();!(x=m.n()).done;){var y=x.value;this.atlasManager.ensureGlyphs(y,h)}}catch(_){m.e(_)}finally{m.f()}this.atlasManager.flush()}},{key:"kill",value:function(){var b=this.normalProgram.gl;this.atlasTexture&&(b.deleteTexture(this.atlasTexture),this.atlasTexture=null),this.atlasManager.destroy(),this.labelGlyphCache.clear(),te(v,"kill",this,3)([])}}])})(jn);return S(c,"labelMargin",l),S(c,"zoomToLabelSizeRatioFunction",u),new c(n,a,t)}var Zs=`#version 300 es
precision highp float;

in float v_edgeDist;

// R32F target: only the .r channel is stored.
out vec4 fragColor;

void main() {
  fragColor = vec4(v_edgeDist, 0.0, 0.0, 0.0);
}
`;function $s(n,a,t){var e=Zt(n),r=Je(n).map(function(f){return"uniform ".concat(f.type," ").concat(f.name,";")}).join(`
`),i=qa(n,t),o=i.code,s=i.multiShape,l=Tt(n,a),u=Object.keys(l.specs).map(function(f){return"float v_".concat(f,";")}).join(`
`),d=xt(l,{varPrefix:"nodeAttr",baseTexelExpr:"nodeIdx * u_layerAttributeTexelsPerNode",textureWidthUniform:"u_layerAttributeTextureWidth",textureSamplerUniform:"u_layerAttributeTexture"}),c=d.fetchCode,p=d.varyingAssignments,v=`#version 300 es
precision highp float;

uniform float u_cameraAngle;
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform float u_frameTextureWidth;
uniform float u_frameTextureHeight;
uniform sampler2D u_layerAttributeTexture;
uniform int u_layerAttributeTextureWidth;
uniform int u_layerAttributeTexelsPerNode;
`.concat(r,`

in float a_nodeIndex;     // node-data texture index (also the target frame texel)
in float a_positionMode;  // 0=right 1=left 2=above 3=below 4=over
in float a_labelAngle;    // intrinsic label angle (radians)

out float v_edgeDist;

// Shape attributes (plain globals: this pass is vertex-only)
`).concat(u,`

`).concat(me,`
`).concat(Le,`
`).concat(e,`
`).concat(o,`
`).concat(Bn,`

void main() {
  int nodeIdx = int(a_nodeIndex);
`).concat(c,`
`).concat(p,`
  `).concat(s?`// Multi-shape: the shape id lives in the node-data texture's .w channel:
  g_shapeId = int(readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx).w);`:"// Single-shape mode, shape id not needed",`

  // Per-node rotation alignment (0 = viewport, 1 = graph).
  vec4 nodeFlags = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, nodeIdx);
  float nodeRotation = nodeFlags.r;
  float labelRotation = nodeFlags.g;

  // Effective angle: intrinsic (style-given) plus the camera angle when the label
  // is graph-aligned. The companions place the box at this same angle.
  float effectiveAngle = a_labelAngle - labelRotation * u_cameraAngle;

  // The "over" mode (4) sits on the node center, so it has no edge distance.
  float edgeDist = 0.0;
  if (a_positionMode < 4.0) {
    vec2 screenDir = getLabelDirection(a_positionMode);
    // Rotate by the effective label angle. Inlined rather than via rotate2D()
    // because the shape SDFs (getShapeGLSLForShapes) already define that helper
    // for multi-shape programs, and redefining it would be a GLSL error.
    float ea_c = cos(effectiveAngle);
    float ea_s = sin(effectiveAngle);
    vec2 rotatedScreenDir = mat2(ea_c, -ea_s, ea_s, ea_c) * screenDir;
    // Screen (Y-down) -> SDF (Y-up).
    vec2 sdfDir = vec2(rotatedScreenDir.x, -rotatedScreenDir.y);
    // Counter-rotate into the shape's local frame for graph-aligned nodes, so the
    // boundary is queried against the shape's actual on-screen orientation.
    float nodeCa = -u_cameraAngle * nodeRotation;
    float nc = cos(nodeCa), ns = sin(nodeCa);
    sdfDir = mat2(nc, -ns, ns, nc) * sdfDir;
    edgeDist = findEdgeDistance(sdfDir, 1.0);
  }
  v_edgeDist = edgeDist;

  // Scatter to this node's texel center in the frame texture.
  float x = mod(a_nodeIndex, u_frameTextureWidth);
  float y = floor(a_nodeIndex / u_frameTextureWidth);
  vec2 ndc = (vec2(x, y) + 0.5) / vec2(u_frameTextureWidth, u_frameTextureHeight) * 2.0 - 1.0;
  gl_Position = vec4(ndc, 0.0, 1.0);
  gl_PointSize = 1.0;
}
`);return v}var qn=(function(){function n(a,t){X(this,n),S(this,"uniformLocations",{});var e=t.shapes,r=t.layers,i=t.shapeGlobalIds;if(e.length===0)throw new Error("NodeLabelFramePass: at least one shape must be provided");this.gl=a,this.shapeUniforms=Je(e),this.hasAttributeData=Object.keys(Tt(e,r).offsets).length>0,this.vertexShader=qt(a,$s(e,r,i)),this.fragmentShader=Yt(a,Zs),this.program=Kt(a,[this.vertexShader,this.fragmentShader]);var o=["u_cameraAngle","u_nodeDataTexture","u_nodeDataTextureWidth","u_frameTextureWidth","u_frameTextureHeight","u_layerAttributeTexture","u_layerAttributeTextureWidth","u_layerAttributeTexelsPerNode"].concat(H(this.shapeUniforms.map(function(h){return h.name}))),s=G(o),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;this.uniformLocations[u]=a.getUniformLocation(this.program,u)}}catch(h){s.e(h)}finally{s.f()}var d=n.FLOATS_PER_POINT*4;this.vao=a.createVertexArray(),this.buffer=a.createBuffer(),a.bindVertexArray(this.vao),a.bindBuffer(a.ARRAY_BUFFER,this.buffer);var c=G([["a_nodeIndex",0],["a_positionMode",4],["a_labelAngle",8]]),p;try{for(c.s();!(p=c.n()).done;){var v=Z(p.value,2),f=v[0],b=v[1],g=a.getAttribLocation(this.program,f);g>=0&&(a.enableVertexAttribArray(g),a.vertexAttribPointer(g,1,a.FLOAT,!1,d,b))}}catch(h){c.e(h)}finally{c.f()}a.bindVertexArray(null)}return j(n,[{key:"run",value:function(t,e,r,i,o){if(e!==0){var s=this.gl;s.useProgram(this.program),s.bindVertexArray(this.vao),s.bindBuffer(s.ARRAY_BUFFER,this.buffer),s.bufferData(s.ARRAY_BUFFER,t.subarray(0,e*n.FLOATS_PER_POINT),s.DYNAMIC_DRAW);var l=this.uniformLocations;s.uniform1f(l.u_cameraAngle,i.cameraAngle),s.uniform1i(l.u_nodeDataTexture,i.nodeDataTextureUnit),s.uniform1i(l.u_nodeDataTextureWidth,i.nodeDataTextureWidth),s.uniform1f(l.u_frameTextureWidth,r.getTextureWidth()),s.uniform1f(l.u_frameTextureHeight,r.getTextureHeight()),this.hasAttributeData&&o&&(o.bind(Me),l.u_layerAttributeTexture&&s.uniform1i(l.u_layerAttributeTexture,Me),l.u_layerAttributeTextureWidth&&s.uniform1i(l.u_layerAttributeTextureWidth,o.getTextureWidth()),l.u_layerAttributeTexelsPerNode&&s.uniform1i(l.u_layerAttributeTexelsPerNode,o.getTexelsPerItem()));var u=G(this.shapeUniforms),d;try{for(u.s();!(d=u.n()).done;){var c=d.value;Ya(s,this.uniformLocations[c.name],c)}}catch(p){u.e(p)}finally{u.f()}r.bindAsRenderTarget(),s.disable(s.BLEND),s.disable(s.DEPTH_TEST),s.drawArrays(s.POINTS,0,e),s.bindFramebuffer(s.FRAMEBUFFER,null),s.bindVertexArray(null)}}},{key:"kill",value:function(){var t=this.gl;t.deleteProgram(this.program),t.deleteShader(this.vertexShader),t.deleteShader(this.fragmentShader),t.deleteBuffer(this.buffer),t.deleteVertexArray(this.vao)}}])})();S(qn,"FLOATS_PER_POINT",3);function Yn(n,a,t,e,r){var i,o=e.label,s=o===void 0?{}:o,l=e.shapes;if(l.length===0)throw new Error("createNodeProgram: at least one shape must be provided in 'shapes'");var u={},d=[],c;l.forEach(function(R,E){var D=Ga(R);E===0&&(c=D),u[R.name]=E,d[E]=Qe(D)});var p=H(e.layers),v=Nn({shapes:l,layers:p,shapeGlobalIds:l.length>1?d:void 0,antialias:r}),f=lr(n,null,t,{label:s}),b=ar(n,null,t,{shapes:l,layers:p,getAttributeTexture:function(){return T.getAttributeTexture()},label:s,shapeGlobalIds:l.length>1?d:void 0}),g=js(n,a,t,{label:s}),h=e.labelAttachments&&Object.keys(e.labelAttachments).length>0?Hs(n,null,t,{label:s}):null,m=new qn(n,{shapes:l,layers:p,shapeGlobalIds:l.length>1?d:void 0}),x=Xn(l,p),y=fe(x),_=(i=(function(R){function E(D,P,w){var A;X(this,E),A=Q(this,E,[D,P,w]),S(A,"layerLifecycles",new Map),S(A,"layersNeedingRegeneration",new Set),S(A,"attrDescriptors",[]),A._pickingBuffer=P;var F=_.layerTextures.get(D);F||(F=new Un(D,y),_.layerTextures.set(D,F)),A.layerAttributeTexture=F;var L=_.textureRefCounts.get(D)||0;_.textureRefCounts.set(D,L+1),A.packedAttributeData=new Float32Array(y.floatsPerItem),p.forEach(function(N,z){if(N.lifecycle){var I={gl:D,renderer:{refresh:function(){return w.refresh()}},getUniformLocation:function(W){return D.getUniformLocation(A.normalProgram.program,W)},requestShaderRegeneration:function(){A.layersNeedingRegeneration.add(z)},requestRefresh:function(){w.refresh()}},C=N.lifecycle(I);A.layerLifecycles.set(z,C)}}),A.layerLifecycles.forEach(function(N){var z;(z=N.init)===null||z===void 0||z.call(N)});var k=new Map;return A.layerLifecycles.forEach(function(N,z){N.getAttributeData&&k.set(z,N)}),A.attrDescriptors=Hn(x,y,k),A}return J(E,R),j(E,[{key:"getDefinition",value:function(){var P=WebGL2RenderingContext,w=P.FLOAT,A=P.TRIANGLE_STRIP;return{VERTICES:4,VERTEX_SHADER_SOURCE:v.vertexShader,FRAGMENT_SHADER_SOURCE:v.fragmentShader,METHOD:A,UNIFORMS:v.uniforms,ATTRIBUTES:v.attributes,CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:w}],CONSTANT_DATA:[[-1,-1],[1,-1],[-1,1],[1,1]]}}},{key:"maybeRegenerateShaders",value:function(){var P=this;if(this.layersNeedingRegeneration.size!==0){p=p.map(function(z,I){if(P.layersNeedingRegeneration.has(I)){var C=P.layerLifecycles.get(I);if(C!=null&&C.regenerate){var M=C.regenerate();return O(O({},M),{},{lifecycle:z.lifecycle})}}return z}),this.layersNeedingRegeneration.clear(),v=Nn({shapes:l,layers:p,shapeGlobalIds:l.length>1?d:void 0,antialias:this.renderer.getSetting("antialiasNodes")});var w=this.normalProgram.gl,A=this.normalProgram,F=A.program,L=A.buffer,k=A.vertexShader,N=A.fragmentShader;w.deleteProgram(F),w.deleteBuffer(L),w.deleteShader(k),w.deleteShader(N),this.normalProgram=this.getProgramInfo("normal",w,v.vertexShader,v.fragmentShader,this._pickingBuffer)}}},{key:"allocateNode",value:function(P){this.layerAttributeTexture.allocate(P)}},{key:"freeNode",value:function(P){this.layerAttributeTexture.free(P)}},{key:"getAttributeTexture",value:function(){return this.layerAttributeTexture}},{key:"uploadLayerTexture",value:function(){this.layerAttributeTexture.upload()}},{key:"process",value:function(P,w,A,F,L){var k=w*this.STRIDE;if(A.visibility==="hidden"){for(var N=k+this.STRIDE;k<N;k++)this.floats[k]=0;this.floats[w*this.STRIDE]=Gi;return}this.processVisibleItem(Ie(P),k,A,F,L)}},{key:"processVisibleItem",value:function(P,w,A,F,L){var k,N=this.floats,z=this.ints;if(N[w++]=F,z[w++]=P,N[w++]=(k=A.opacity)!==null&&k!==void 0?k:1,y.floatsPerItem!==0){var I=this.packedAttributeData;Vn(this.attrDescriptors,A,I,A.color,this.layerLifecycles,0),this.layerAttributeTexture.updateAllAttributes(L,I)}}},{key:"setUniforms",value:function(P,w){var A=this,F=w.gl,L=w.uniformLocations;L.u_matrix&&F.uniformMatrix3fv(L.u_matrix,!1,P.matrix),L.u_sizeRatio&&F.uniform1f(L.u_sizeRatio,P.sizeRatio),L.u_correctionRatio&&F.uniform1f(L.u_correctionRatio,P.correctionRatio),L.u_pickingPadding&&F.uniform1f(L.u_pickingPadding,P.nodePickingPadding),L.u_cameraAngle&&F.uniform1f(L.u_cameraAngle,P.cameraAngle),L.u_nodeDataTexture&&F.uniform1i(L.u_nodeDataTexture,P.nodeDataTextureUnit),L.u_nodeDataTextureWidth&&F.uniform1i(L.u_nodeDataTextureWidth,P.nodeDataTextureWidth),L.u_layerAttributeTexture&&(this.layerAttributeTexture.bind(Me),F.uniform1i(L.u_layerAttributeTexture,Me)),L.u_layerAttributeTextureWidth&&F.uniform1i(L.u_layerAttributeTextureWidth,this.layerAttributeTexture.getTextureWidth()),L.u_layerAttributeTexelsPerNode&&F.uniform1i(L.u_layerAttributeTexelsPerNode,this.layerAttributeTexture.getTexelsPerItem()),l.forEach(function(k){k.uniforms.forEach(function(N){A.setTypedUniform(N,w)})}),p.forEach(function(k){k.uniforms.forEach(function(N){A.setTypedUniform(N,w)})})}},{key:"renderProgram",value:function(P,w){this.maybeRegenerateShaders();var A=w.gl,F=w.program;A.useProgram(F),w===this.normalProgram&&this.layerLifecycles.forEach(function(L){var k;(k=L.beforeRender)===null||k===void 0||k.call(L)}),te(E,"renderProgram",this,3)([P,w])}},{key:"kill",value:function(){this.layerLifecycles.forEach(function(A){var F;(F=A.kill)===null||F===void 0||F.call(A)}),this.layerLifecycles.clear();var P=this.normalProgram.gl,w=(_.textureRefCounts.get(P)||1)-1;w<=0?(this.layerAttributeTexture.kill(),_.layerTextures.delete(P),_.textureRefCounts.delete(P)):_.textureRefCounts.set(P,w),te(E,"kill",this,3)([])}}])})(Pe),S(i,"layerTextures",new WeakMap),S(i,"textureRefCounts",new WeakMap),i),T=new _(n,null,t);return{nodeProgram:T,labelProgram:f,backdropProgram:b,labelBackgroundProgram:g,attachmentProgram:h,framePass:m,shapeSlug:c,shapeNameToIndex:l.length>1?u:void 0,shapeGlobalIds:l.length>1?d:void 0}}var Ge=6;function en(n){var a=n.offsets,t=n.specs,e=n.floatsPerItem,r=Object.keys(a);if(r.length===0||e===0)return{uniformDeclarations:"",uniformNames:[],vertexVaryingDeclarations:"",fragmentVaryingDeclarations:"",fetchCode:"",varyingAssignments:""};var i=`
uniform sampler2D u_edgeAttributeTexture;
uniform int u_edgeAttributeTextureWidth;
uniform int u_edgeAttributeTexelsPerEdge;`,o=["u_edgeAttributeTexture","u_edgeAttributeTextureWidth","u_edgeAttributeTexelsPerEdge"],s=r.map(function(v){var f=t[v].size===1?"float":"vec".concat(t[v].size);return"".concat(f," v_").concat(v,";")}),l=s.map(function(v){return"out ".concat(v)}).join(`
`),u=s.map(function(v){return"in ".concat(v)}).join(`
`),d=xt(n,{varPrefix:"attr",baseTexelExpr:"edgeIdx * u_edgeAttributeTexelsPerEdge",textureWidthUniform:"u_edgeAttributeTextureWidth",textureSamplerUniform:"u_edgeAttributeTexture"}),c=d.fetchCode,p=d.varyingAssignments;return{uniformDeclarations:i,uniformNames:o,vertexVaryingDeclarations:l,fragmentVaryingDeclarations:u,fetchCode:c,varyingAssignments:p}}function Qs(n){return`
float findSourceClampT_`.concat(n,`(vec2 source, float sourceSize, int sourceShapeId, float sourceRotateAlign, vec2 target, float margin) {
  float lo = 0.0, hi = 0.5;
  float nodeExtent = sourceSize * u_correctionRatio / u_sizeRatio * 2.0;
  float effectiveSize = 1.0 - u_correctionRatio / nodeExtent;

  // Counter-rotate the query point so viewport-aligned nodes (rotateAlign=0) are
  // clamped against their on-screen orientation; graph-aligned nodes skip it.
  float ca = u_cameraAngle * (1.0 - sourceRotateAlign);
  float rc = cos(ca), rs = sin(ca);
  mat2 rot = mat2(rc, -rs, rs, rc);

  for (int i = 0; i < 12; i++) {
    float mid = (lo + hi) * 0.5;
    vec2 pos = path_`).concat(n,`_position(mid, source, target);
    vec2 localPos = rot * ((pos - source) / nodeExtent);
    float sdf = querySDF(sourceShapeId, localPos, effectiveSize);
    if (sdf < 0.0) lo = mid;
    else hi = mid;
  }

  float pathLen = path_`).concat(n,`_length(source, target);
  float marginT = (margin * u_correctionRatio / u_sizeRatio) / pathLen;
  return (lo + hi) * 0.5 + marginT;
}
`)}function Js(n){return`
float findTargetClampT_`.concat(n,`(vec2 source, vec2 target, float targetSize, int targetShapeId, float targetRotateAlign, float margin) {
  float lo = 0.5, hi = 1.0;
  float nodeExtent = targetSize * u_correctionRatio / u_sizeRatio * 2.0;
  float effectiveSize = 1.0 - u_correctionRatio / nodeExtent;

  // See findSourceClampT_ for the rotation rationale.
  float ca = u_cameraAngle * (1.0 - targetRotateAlign);
  float rc = cos(ca), rs = sin(ca);
  mat2 rot = mat2(rc, -rs, rs, rc);

  for (int i = 0; i < 12; i++) {
    float mid = (lo + hi) * 0.5;
    vec2 pos = path_`).concat(n,`_position(mid, source, target);
    vec2 localPos = rot * ((pos - target) / nodeExtent);
    float sdf = querySDF(targetShapeId, localPos, effectiveSize);
    if (sdf < 0.0) hi = mid;
    else lo = mid;
  }

  float pathLen = path_`).concat(n,`_length(source, target);
  float marginT = (margin * u_correctionRatio / u_sizeRatio) / pathLen;
  return (lo + hi) * 0.5 - marginT;
}
`)}function Wi(n){return`
// Auto-generated numerical tangent (from position via finite differences)
vec2 path_`.concat(n,`_tangent(float t, vec2 source, vec2 target) {
  float epsilon = 0.001;
  float t1 = max(0.0, t - epsilon);
  float t2 = min(1.0, t + epsilon);
  vec2 p1 = path_`).concat(n,`_position(t1, source, target);
  vec2 p2 = path_`).concat(n,`_position(t2, source, target);
  return normalize(p2 - p1);
}

// Auto-generated normal (perpendicular to tangent)
vec2 path_`).concat(n,`_normal(float t, vec2 source, vec2 target) {
  vec2 tangent = path_`).concat(n,`_tangent(t, source, target);
  return vec2(-tangent.y, tangent.x);
}
`)}function ur(n){return`
// Rotate a 2D vector by angle (counter-clockwise)
vec2 `.concat(n,`_rotate(vec2 v, float angle) {
  float c = cos(angle);
  float s = sin(angle);
  return vec2(c * v.x - s * v.y, s * v.x + c * v.y);
}
`)}function el(n){return`
// Auto-generated path length (samples position 16 times)
float path_`.concat(n,`_length(vec2 source, vec2 target) {
  float len = 0.0;
  vec2 prev = path_`).concat(n,`_position(0.0, source, target);
  for (int i = 1; i <= 16; i++) {
    float t = float(i) / 16.0;
    vec2 curr = path_`).concat(n,`_position(t, source, target);
    len += length(curr - prev);
    prev = curr;
  }
  return len;
}
`)}function tl(n){return`
// Auto-generated closest_t (coarse sample + ternary search)
float path_`.concat(n,`_closest_t(vec2 p, vec2 source, vec2 target) {
  // Coarse search: find best among 10 samples
  float bestT = 0.0;
  float bestDist = 1e10;
  for (int i = 0; i <= 10; i++) {
    float t = float(i) / 10.0;
    vec2 pos = path_`).concat(n,`_position(t, source, target);
    float d = length(p - pos);
    if (d < bestDist) {
      bestDist = d;
      bestT = t;
    }
  }

  // Refine with ternary search
  float lo = max(0.0, bestT - 0.1);
  float hi = min(1.0, bestT + 0.1);
  for (int i = 0; i < 10; i++) {
    float mid1 = lo + (hi - lo) / 3.0;
    float mid2 = hi - (hi - lo) / 3.0;
    float d1 = length(p - path_`).concat(n,`_position(mid1, source, target));
    float d2 = length(p - path_`).concat(n,`_position(mid2, source, target));
    if (d1 < d2) {
      hi = mid2;
    } else {
      lo = mid1;
    }
  }
  return (lo + hi) * 0.5;
}
`)}function nl(n){return`
// Auto-generated signed distance (via closest_t + normal)
float path_`.concat(n,`_distance(vec2 p, vec2 source, vec2 target) {
  float closestT = path_`).concat(n,`_closest_t(p, source, target);
  vec2 closest = path_`).concat(n,`_position(closestT, source, target);
  vec2 diff = p - closest;
  float dist = length(diff);
  if (dist < 0.0001) return 0.0;

  // Get normal at closest point
  vec2 normal = path_`).concat(n,`_normal(closestT, source, target);
  return dist * sign(dot(diff, normal));
}
`)}function al(n){return`
// Auto-generated t_at_distance (binary search)
float path_`.concat(n,`_t_at_distance(float targetDist, vec2 source, vec2 target) {
  if (targetDist <= 0.0) return 0.0;

  float totalLen = path_`).concat(n,`_length(source, target);
  if (targetDist >= totalLen) return 1.0;

  // Binary search for t
  float lo = 0.0, hi = 1.0;
  for (int i = 0; i < 12; i++) {
    float mid = (lo + hi) * 0.5;

    // Compute arc length from 0 to mid
    float arcLen = 0.0;
    vec2 prev = path_`).concat(n,`_position(0.0, source, target);
    for (int j = 1; j <= 8; j++) {
      float t = mid * float(j) / 8.0;
      vec2 curr = path_`).concat(n,`_position(t, source, target);
      arcLen += length(curr - prev);
      prev = curr;
    }

    if (arcLen < targetDist) {
      lo = mid;
    } else {
      hi = mid;
    }
  }
  return (lo + hi) * 0.5;
}
`)}function wn(n,a){var t=new RegExp("\\b(float|vec[234]|void|int|bool)\\s+".concat(a,"\\s*\\("));return t.test(n)}function Ui(n,a){var t=[];return wn(a,"path_".concat(n,"_length"))||t.push(el(n)),wn(a,"path_".concat(n,"_closest_t"))||t.push(tl(n)),wn(a,"path_".concat(n,"_distance"))||t.push(nl(n)),wn(a,"path_".concat(n,"_t_at_distance"))||t.push(al(n)),t.length>0?`
// ============================================================================
// Auto-generated fallback functions (path only provided position)
// ============================================================================
`.concat(t.join(`
`)):""}function Hi(n){var a,t,e,r=n.paths,i=n.layers,o=(a=n.extremities)!==null&&a!==void 0?a:[];if(r.length===0)throw new Error("At least one path is required in 'paths'");if(i.length===0)throw new Error("At least one layer is required in 'layers'");var s=(t=n.defaultHead)!==null&&t!==void 0?t:"none",l=(e=n.defaultTail)!==null&&e!==void 0?e:"none";return{paths:r,extremities:o,layers:i,path:r[0],layer:i[0],defaultHead:s,defaultTail:l}}var Vi=WebGL2RenderingContext,jt=Vi.FLOAT,Ai=Vi.UNSIGNED_BYTE;function rl(n,a,t){var e=new Set(["u_matrix","u_sizeRatio","u_correctionRatio","u_zoomRatio","u_pixelRatio","u_cameraAngle","u_minEdgeThickness","u_pickingPadding","u_nodeDataTexture","u_nodeDataTextureWidth","u_edgeDataTexture","u_edgeDataTextureWidth","u_edgeFrameTexture","u_edgeFrameTextureWidth","u_edgeAttributeTexture","u_edgeAttributeTextureWidth","u_edgeAttributeTexelsPerEdge"]),r=new Set(e);return n.forEach(function(i){return i.uniforms.forEach(function(o){return r.add(o.name)})}),a.forEach(function(i){return i.uniforms.forEach(function(o){return r.add(o.name)})}),t.forEach(function(i){return i.uniforms.forEach(function(o){return r.add(o.name)})}),Array.from(r)}function dr(n){var a=new Set,t=[],e=G(n),r;try{for(e.s();!(r=e.n()).done;){var i=r.value;a.has(i.name)||(a.add(i.name),t.push("// Path: ".concat(i.name)),t.push(i.glsl),t.push(Wi(i.name)),t.push(Ui(i.name,i.glsl)))}}catch(o){e.e(o)}finally{e.f()}return t.join(`

`)}function il(n){var a=[],t=G(n),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;a.push("// Extremity: ".concat(r.name)),a.push(r.glsl)}}catch(i){t.e(i)}finally{t.f()}return a.join(`

`)}var ol=[{queryName:"queryPathPosition",pathFunc:"position",returnType:"vec2",params:"float t, vec2 source, vec2 target",args:"t, source, target"},{queryName:"queryPathTangent",pathFunc:"tangent",returnType:"vec2",params:"float t, vec2 source, vec2 target",args:"t, source, target"},{queryName:"queryPathNormal",pathFunc:"normal",returnType:"vec2",params:"float t, vec2 source, vec2 target",args:"t, source, target"},{queryName:"queryPathLength",pathFunc:"length",returnType:"float",params:"vec2 source, vec2 target",args:"source, target"},{queryName:"queryPathClosestT",pathFunc:"closest_t",returnType:"float",params:"vec2 p, vec2 source, vec2 target",args:"p, source, target"}];function sl(n,a){var t=a.queryName,e=a.pathFunc,r=a.returnType,i=a.params,o=a.args;if(n.length===1)return"".concat(r," ").concat(t,"(int pathId, ").concat(i,`) {
  return path_`).concat(n[0].name,"_").concat(e,"(").concat(o,`);
}`);var s=n.map(function(l,u){return"    case ".concat(u,": return path_").concat(l.name,"_").concat(e,"(").concat(o,");")}).join(`
`);return"".concat(r," ").concat(t,"(int pathId, ").concat(i,`) {
  switch (pathId) {
`).concat(s,`
    default: return path_`).concat(n[0].name,"_").concat(e,"(").concat(o,`);
  }
}`)}function cr(n){return ol.map(function(a){return sl(n,a)}).join(`

`)}function ll(n){if(n.length===1)return`float queryExtremitySDF(int extremityId, vec2 uv, float lengthRatio, float widthRatio) {
  return extremity_`.concat(n[0].name,`(uv, lengthRatio, widthRatio);
}`);var a=n.map(function(t,e){return"    case ".concat(e,": return extremity_").concat(t.name,"(uv, lengthRatio, widthRatio);")}).join(`
`);return`float queryExtremitySDF(int extremityId, vec2 uv, float lengthRatio, float widthRatio) {
  switch (extremityId) {
`.concat(a,`
    default: return extremity_`).concat(n[0].name,`(uv, lengthRatio, widthRatio);
  }
}`)}function ul(n){var a=[],t=G(n),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;a.push(Qs(r.name)),a.push(Js(r.name))}}catch(s){t.e(s)}finally{t.f()}if(n.length===1)a.push(`
float queryFindSourceClampT(int pathId, vec2 source, float sourceSize, int sourceShapeId, float sourceRotateAlign, vec2 target, float margin) {
  return findSourceClampT_`.concat(n[0].name,`(source, sourceSize, sourceShapeId, sourceRotateAlign, target, margin);
}

float queryFindTargetClampT(int pathId, vec2 source, vec2 target, float targetSize, int targetShapeId, float targetRotateAlign, float margin) {
  return findTargetClampT_`).concat(n[0].name,`(source, target, targetSize, targetShapeId, targetRotateAlign, margin);
}`));else{var i=n.map(function(s,l){return"    case ".concat(l,": return findSourceClampT_").concat(s.name,"(source, sourceSize, sourceShapeId, sourceRotateAlign, target, margin);")}).join(`
`),o=n.map(function(s,l){return"    case ".concat(l,": return findTargetClampT_").concat(s.name,"(source, target, targetSize, targetShapeId, targetRotateAlign, margin);")}).join(`
`);a.push(`
float queryFindSourceClampT(int pathId, vec2 source, float sourceSize, int sourceShapeId, float sourceRotateAlign, vec2 target, float margin) {
  switch (pathId) {
`.concat(i,`
    default: return findSourceClampT_`).concat(n[0].name,`(source, sourceSize, sourceShapeId, sourceRotateAlign, target, margin);
  }
}

float queryFindTargetClampT(int pathId, vec2 source, vec2 target, float targetSize, int targetShapeId, float targetRotateAlign, float margin) {
  switch (pathId) {
`).concat(o,`
    default: return findTargetClampT_`).concat(n[0].name,`(source, target, targetSize, targetShapeId, targetRotateAlign, margin);
  }
}`))}return a.join(`

`)}function dl(n,a,t,e,r){var i=fe([].concat(H(n),H(t))),o=en(i),s=Tt(e,r),l=Object.keys(s.offsets),u=function(R){var E=s.specs[R].size;return E===1?"float":"vec".concat(E)},d=l.map(function(T){return"".concat(u(T)," v_source_").concat(T,`;
`).concat(u(T)," v_target_").concat(T,";")}).join(`
`),c=xt(s,{varPrefix:"srcNodeAttr",baseTexelExpr:"srcIdx * u_layerAttributeTexelsPerNode",textureWidthUniform:"u_layerAttributeTextureWidth",textureSamplerUniform:"u_layerAttributeTexture",outputPrefix:"v_source_"}),p=xt(s,{varPrefix:"tgtNodeAttr",baseTexelExpr:"tgtIdx * u_layerAttributeTexelsPerNode",textureWidthUniform:"u_layerAttributeTextureWidth",textureSamplerUniform:"u_layerAttributeTexture",outputPrefix:"v_target_"}),v=l.map(function(T){return"".concat(u(T)," g_").concat(T,";")}).join(`
`),f=l.map(function(T){return"  g_".concat(T," = v_source_").concat(T,";")}).join(`
`),b=l.map(function(T){return"  g_".concat(T," = v_target_").concat(T,";")}).join(`
`),g=new Set,h=[],m=function(R){g.has(R.name)||(g.add(R.name),h.push("uniform ".concat(R.type," ").concat(R.name,";")))};n.forEach(function(T){return T.uniforms.forEach(m)}),a.forEach(function(T){return T.uniforms.forEach(m)});var x=a.map(function(T){return Y(T.widthFactor)}).join(", "),y=Math.max.apply(Math,H(n.map(function(T){return T.minBodyLengthRatio||0}))),_=`#version 300 es

// Node and edge data textures
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_edgeDataTexture;
uniform int u_edgeDataTextureWidth;

// Edge attribute texture (for path-specific attributes like curvature)
`.concat(o.uniformDeclarations,`

// Node attribute texture (for node shape attributes)
uniform sampler2D u_layerAttributeTexture;
uniform int u_layerAttributeTextureWidth;
uniform int u_layerAttributeTexelsPerNode;

// Render params needed for clamping
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
uniform float u_minEdgeThickness;

// Edge-frame texture dimensions, for scattering each point to its texel
uniform float u_frameTextureWidth;
uniform float u_frameTextureHeight;

// Custom path/extremity uniforms
`).concat(h.join(`
`),`

// Path attribute varyings \u2014 assigned so path functions can read them as globals
`).concat(o.vertexVaryingDeclarations,`

// Node size varyings \u2014 read by path functions like loop
out float v_sourceNodeSize;
out float v_targetNodeSize;

// Node shape attributes per endpoint, and the ones querySDF reads
`).concat(d,`
`).concat(v,`

// Scattered output written to the edge-frame texel: [tStart, tEnd, straightenFactor, pathLength]
out vec4 v_clamp;

// Extremity width factor array (needed for extremityScale computation)
const float EXTREMITY_WIDTH_FACTORS[`).concat(a.length,"] = float[](").concat(x,`);

// Node-data fetch helpers (geometry texel + rotation-flags texel)
`).concat(me,`
`).concat(Le,`

// Shape SDFs for node boundary clamping
`).concat(Oa(),`
`).concat(Ba(new Set(l)),`

// Path functions
`).concat(dr(n),`
`).concat(cr(n),`
`).concat(ul(n),`

void main() {
  // One point per edge-data row; the row index is the edge-frame texel target.
  int edgeIdx = gl_VertexID;
  int texel0Idx = edgeIdx * 2;
  int texel1Idx = edgeIdx * 2 + 1;
  ivec2 edgeTexCoord0 = ivec2(texel0Idx % u_edgeDataTextureWidth, texel0Idx / u_edgeDataTextureWidth);
  ivec2 edgeTexCoord1 = ivec2(texel1Idx % u_edgeDataTextureWidth, texel1Idx / u_edgeDataTextureWidth);
  vec4 edgeData0 = texelFetch(u_edgeDataTexture, edgeTexCoord0, 0);
  vec4 edgeData1 = texelFetch(u_edgeDataTexture, edgeTexCoord1, 0);

  int srcIdx = int(edgeData0.x);
  int tgtIdx = int(edgeData0.y);
  float a_thickness = edgeData0.z;
  float a_headLengthRatio = edgeData1.x;
  float a_tailLengthRatio = edgeData1.y;
  int pathId = int(edgeData1.z);
  int extremityPacked = int(edgeData1.w);
  int headId = extremityPacked >> 4;
  int tailId = extremityPacked & 15;

  // Fetch path/layer attributes and assign to path-function globals
`).concat(o.fetchCode,`
`).concat(o.varyingAssignments,`

  // Fetch node shape attributes for both endpoints
`).concat(c.fetchCode,`
`).concat(c.varyingAssignments,`
`).concat(p.fetchCode,`
`).concat(p.varyingAssignments,`

  // Fetch node geometry (texel 0) and rotation flags (texel 1).
  vec4 srcNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx);
  vec4 tgtNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx);

  vec2 a_source = srcNodeData.xy;
  vec2 a_target = tgtNodeData.xy;
  float a_sourceSize = srcNodeData.z;
  float a_targetSize = tgtNodeData.z;
  float a_sourceShapeId = srcNodeData.w;
  float a_targetShapeId = tgtNodeData.w;
  // Per-node rotation alignment (0 = viewport, 1 = graph), for boundary clamping.
  float a_sourceRotateAlign = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx).r;
  float a_targetRotateAlign = readNodeFlags(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx).r;

  v_sourceNodeSize = a_sourceSize;
  v_targetNodeSize = a_targetSize;

  float headLengthRatio = a_headLengthRatio;
  float tailLengthRatio = a_tailLengthRatio;
  float headWidthFactor = EXTREMITY_WIDTH_FACTORS[headId];
  float tailWidthFactor = EXTREMITY_WIDTH_FACTORS[tailId];
  float minBodyLengthRatio = `).concat(Y(y),`;

  // Thickness in WebGL units (needed to compute clamping margin and extremity lengths)
  float pixelsThickness = max(a_thickness, u_minEdgeThickness * u_sizeRatio);
  float webGLThickness = pixelsThickness * u_correctionRatio / u_sizeRatio;

  // SDF clamping: find where the edge body meets the node boundaries. Always
  // searched (ungated) so labels get a true boundary clamp; the body re-applies
  // its extremity gating in-shader.
`).concat(f,`
  float tStart = queryFindSourceClampT(pathId, a_source, a_sourceSize, int(a_sourceShapeId), a_sourceRotateAlign, a_target, 0.0);
`).concat(b,`
  float tEnd = queryFindTargetClampT(pathId, a_source, a_target, a_targetSize, int(a_targetShapeId), a_targetRotateAlign, 0.0);

  // straightenFactor (frame .z) is consumed only by the body, which runs to the
  // node center when an extremity is absent. Derive the straightening math from
  // these gated clamps \u2014 not the ungated boundary ones above \u2014 so it matches the
  // geometry it drives. The ungated tStart/tEnd remain what labels read.
  float bodyTStart = tailLengthRatio > 0.0 ? tStart : 0.0;
  float bodyTEnd = headLengthRatio > 0.0 ? tEnd : 1.0;

  // Path length and zone boundaries (needed for straightening check)
  float pathLength = queryPathLength(pathId, a_source, a_target);
  float visibleLength = pathLength * (bodyTEnd - bodyTStart);

  float headLength = headLengthRatio * webGLThickness;
  float tailLength = tailLengthRatio * webGLThickness;
  float minBodyLength = minBodyLengthRatio * webGLThickness;

  float totalNeededLength = headLength + tailLength + minBodyLength;
  float extremityScale = 1.0;
  if (totalNeededLength > visibleLength && totalNeededLength > 0.0001) {
    extremityScale = visibleLength / totalNeededLength;
    headLength *= extremityScale;
    tailLength *= extremityScale;
  }

  float headLengthT = pathLength > 0.0001 ? headLength / pathLength : 0.0;
  float tailLengthT = pathLength > 0.0001 ? tailLength / pathLength : 0.0;

  float tTailEnd = bodyTStart + tailLengthT;
  float tHeadStart = bodyTEnd - headLengthT;
  if (tTailEnd > tHeadStart) {
    float mid = (bodyTStart + bodyTEnd) * 0.5;
    tTailEnd = mid;
    tHeadStart = mid;
  }

  // Straighten factor: blend toward straight line when path twists in extremity zones
  float straightenFactor = 0.0;
  {
    float maxDeviation = 0.0;
    if (tailLengthT > 0.0001) {
      vec2 tailTang = queryPathTangent(pathId, tTailEnd, a_source, a_target);
      vec2 tailChord = queryPathPosition(pathId, bodyTStart, a_source, a_target)
                     - queryPathPosition(pathId, tTailEnd, a_source, a_target);
      float tailChordLen = length(tailChord);
      if (tailChordLen > 0.0001) {
        maxDeviation = max(maxDeviation, 1.0 - dot(-tailTang, tailChord / tailChordLen));
      }
    }
    if (headLengthT > 0.0001) {
      vec2 headTang = queryPathTangent(pathId, tHeadStart, a_source, a_target);
      vec2 headChord = queryPathPosition(pathId, bodyTEnd, a_source, a_target)
                     - queryPathPosition(pathId, tHeadStart, a_source, a_target);
      float headChordLen = length(headChord);
      if (headChordLen > 0.0001) {
        maxDeviation = max(maxDeviation, 1.0 - dot(headTang, headChord / headChordLen));
      }
    }
    straightenFactor = smoothstep(0.035, 0.5, maxDeviation);
  }

  // When straightening, blend the ungated tStart/tEnd (the label-facing clamps)
  // toward straight-line clamp positions.
  if (straightenFactor > 0.001) {
    if (tailLengthRatio > 0.0) {
`).concat(f,`
      float srcExtent = a_sourceSize * u_correctionRatio / u_sizeRatio * 2.0;
      float srcEffective = 1.0 - u_correctionRatio / srcExtent;
      float srcCa = u_cameraAngle * (1.0 - a_sourceRotateAlign);
      mat2 srcRot = mat2(cos(srcCa), -sin(srcCa), sin(srcCa), cos(srcCa));
      float lo = 0.0, hi = 0.5;
      for (int i = 0; i < 12; i++) {
        float mid = (lo + hi) * 0.5;
        vec2 pos = mix(a_source, a_target, mid);
        vec2 localPos = srcRot * ((pos - a_source) / srcExtent);
        float sdf = querySDF(int(a_sourceShapeId), localPos, srcEffective);
        if (sdf < 0.0) lo = mid; else hi = mid;
      }
      tStart = mix(tStart, (lo + hi) * 0.5, straightenFactor);
    }
    if (headLengthRatio > 0.0) {
`).concat(b,`
      float tgtExtent = a_targetSize * u_correctionRatio / u_sizeRatio * 2.0;
      float tgtEffective = 1.0 - u_correctionRatio / tgtExtent;
      float tgtCa = u_cameraAngle * (1.0 - a_targetRotateAlign);
      mat2 tgtRot = mat2(cos(tgtCa), -sin(tgtCa), sin(tgtCa), cos(tgtCa));
      float lo = 0.5, hi = 1.0;
      for (int i = 0; i < 12; i++) {
        float mid = (lo + hi) * 0.5;
        vec2 pos = mix(a_source, a_target, mid);
        vec2 localPos = tgtRot * ((pos - a_target) / tgtExtent);
        float sdf = querySDF(int(a_targetShapeId), localPos, tgtEffective);
        if (sdf < 0.0) hi = mid; else lo = mid;
      }
      tEnd = mix(tEnd, (lo + hi) * 0.5, straightenFactor);
    }
  }

  v_clamp = vec4(tStart, tEnd, straightenFactor, pathLength);

  // Scatter this point to its edge's texel center in the frame texture.
  float x = mod(float(edgeIdx), u_frameTextureWidth);
  float y = floor(float(edgeIdx) / u_frameTextureWidth);
  vec2 ndc = (vec2(x, y) + 0.5) / vec2(u_frameTextureWidth, u_frameTextureHeight) * 2.0 - 1.0;
  gl_Position = vec4(ndc, 0.0, 1.0);
  gl_PointSize = 1.0;
}
`);return _}var In=0,Di=1,kn=2;function cl(n,a,t){var e=[];t&&(e.push([In,0,-1],[In,0,1]),e.push([In,1,-1],[In,1,1]));for(var r=0;r<=n;r++){var i=r/n;e.push([Di,i,-1],[Di,i,1])}return a&&(e.push([kn,0,-1],[kn,0,1]),e.push([kn,1,-1],[kn,1,1])),{data:e,attributes:[{name:"a_zone",size:1,type:jt},{name:"a_zoneT",size:1,type:jt},{name:"a_side",size:1,type:jt}],verticesPerEdge:e.length}}function hl(n,a,t,e){var r=fe([].concat(H(n),H(t))),i=en(r),o=new Set(["u_matrix","u_sizeRatio","u_correctionRatio","u_zoomRatio","u_pixelRatio","u_cameraAngle","u_minEdgeThickness","u_pickingPadding","u_nodeDataTexture"]),s=new Set,l=[],u=function(h){!o.has(h.name)&&!s.has(h.name)&&(s.add(h.name),l.push("uniform ".concat(h.type," ").concat(h.name,";")))};n.forEach(function(g){return g.uniforms.forEach(u)}),a.forEach(function(g){return g.uniforms.forEach(u)}),t.forEach(function(g){return g.uniforms.forEach(u)});var d=e.map(function(g){var h=g.size===1?"float":"vec".concat(g.size);return"in ".concat(h," ").concat(g.name,";")}).join(`
`),c=a.map(function(g){return Y(g.widthFactor)}).join(", "),p=Math.max.apply(Math,H(n.map(function(g){return g.minBodyLengthRatio||0}))),v=t.some(function(g){return g.needsNodeColors}),f=n.some(function(g){return g.needsNodeSize}),b=`#version 300 es

// Constant attributes (per vertex)
`.concat(d,`

// Per-edge attributes
// Edge data (source/target indices, thickness, extremity ratios, path/extremity IDs)
// is fetched from edge data texture via edge index
in float a_edgeIndex;   // Index into edge data texture
in vec4 a_color;        // Edge color
in vec4 a_id;           // Edge ID for picking
in float a_opacity;     // Edge opacity

// Standard uniforms
uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_zoomRatio;
uniform float u_pixelRatio;
uniform float u_cameraAngle;
uniform float u_minEdgeThickness;
#ifdef PICKING_MODE
uniform float u_pickingPadding;
#endif
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_edgeDataTexture;
uniform int u_edgeDataTextureWidth;
uniform sampler2D u_edgeFrameTexture;
uniform int u_edgeFrameTextureWidth;

// Edge path attribute texture uniforms
`).concat(i.uniformDeclarations,`

// Custom uniforms
`).concat(l.join(`
`),`

// Standard varyings
out vec4 v_color;
out float v_opacity;
out vec4 v_id;
out float v_thickness;       // Edge body thickness (in consistent units)
out float v_t;
out float v_tStart;
out float v_tEnd;
out float v_side;
out float v_antialiasingWidth;  // Anti-aliasing width (normalized: u_correctionRatio / thickness)
out vec2 v_source;
out vec2 v_target;
out float v_edgeLength;
`).concat(f?`
out float v_sourceNodeSize;  // Source node size (mirrored in labels/generator.ts as plain float)
out float v_targetNodeSize;  // Target node size (mirrored in labels/generator.ts as plain float)`:"",`
`).concat(v?`
out vec4 v_sourceColor;
out vec4 v_targetColor;`:"",`
// Zone varyings
out float v_zone;            // 0=tail, 1=body, 2=head
out float v_zoneT;           // Position within zone [0,1]
out float v_headLengthRatio; // Head length as ratio of thickness
out float v_tailLengthRatio; // Tail length as ratio of thickness
out float v_headWidthRatio;  // Head width factor
out float v_tailWidthRatio;  // Tail width factor

// Multi-path/extremity varyings
flat out int v_pathId;
flat out int v_headId;
flat out int v_tailId;

// Path/layer attribute varyings (fetched from edge attribute texture)
`).concat(i.vertexVaryingDeclarations,`

const float bias = 255.0 / 254.0;

// Width factor array for extremities (shared pool for head/tail)
const float EXTREMITY_WIDTH_FACTORS[`).concat(a.length,"] = float[](").concat(c,`);

// All path functions
`).concat(dr(n),`

// Path selector functions
`).concat(cr(n),`

// Node-data fetch helper (geometry texel of the two-texel node stride)
`).concat(me,`
`).concat(v?ja:"",`
// Per-edge clamp from the frame-pass (tStart, tEnd, straightenFactor, pathLength)
`).concat(Ue,`

void main() {
  // Fetch edge data from edge texture (2 texels per edge)
  // Texel 0: sourceNodeIndex, targetNodeIndex, thickness, reserved
  // Texel 1: headLengthRatio, tailLengthRatio, pathId, (headId << 4) | tailId
  int edgeIdx = int(a_edgeIndex);

  // Hidden edges are flagged with a negative row by EdgeProgram.process(). Push
  // the whole primitive outside the clip volume: every vertex lands at the same
  // out-of-range position, so it is fully clipped and rasterizes nothing \u2014
  // neither to the frame buffer nor to the picking buffer.
  if (edgeIdx < 0) {
    gl_Position = vec4(2.0, 0.0, 0.0, 1.0);
    v_color = vec4(0.0);
    v_id = vec4(0.0);
    return;
  }

  int texel0Idx = edgeIdx * 2;
  int texel1Idx = edgeIdx * 2 + 1;
  ivec2 edgeTexCoord0 = ivec2(texel0Idx % u_edgeDataTextureWidth, texel0Idx / u_edgeDataTextureWidth);
  ivec2 edgeTexCoord1 = ivec2(texel1Idx % u_edgeDataTextureWidth, texel1Idx / u_edgeDataTextureWidth);
  vec4 edgeData0 = texelFetch(u_edgeDataTexture, edgeTexCoord0, 0);
  vec4 edgeData1 = texelFetch(u_edgeDataTexture, edgeTexCoord1, 0);

  // Unpack edge data
  int srcIdx = int(edgeData0.x);
  int tgtIdx = int(edgeData0.y);
  float a_thickness = edgeData0.z;
  // edgeData0.w is now reserved (curvature moved to path attribute texture)
  float a_headLengthRatio = edgeData1.x;
  float a_tailLengthRatio = edgeData1.y;
  int pathId = int(edgeData1.z);
  int extremityPacked = int(edgeData1.w);
  int headId = extremityPacked >> 4;
  int tailId = extremityPacked & 15;

  // Fetch path/layer attributes from edge attribute texture
`).concat(i.fetchCode,`

  // Assign path/layer attribute varyings
`).concat(i.varyingAssignments,`

  // Fetch source and target node geometry (texel 0 of the two-texel node stride)
  vec4 srcNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx);
  vec4 tgtNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx);

  vec2 a_source = srcNodeData.xy;
  vec2 a_target = tgtNodeData.xy;
`).concat(f?`
  // Assign node size varyings early (path functions like loops need them during clamping)
  v_sourceNodeSize = srcNodeData.z;
  v_targetNodeSize = tgtNodeData.z;`:"",`
`).concat(v?`
  v_sourceColor = readNodeColor(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx);
  v_targetColor = readNodeColor(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx);`:"",`

  // Convert thickness to WebGL units
  float minThickness = u_minEdgeThickness;
  float pixelsThickness = max(a_thickness, minThickness * u_sizeRatio);
  float webGLThickness = pixelsThickness * u_correctionRatio / u_sizeRatio;

  // Extremity parameters from ID lookups (shared pool)
  float headLengthRatio = a_headLengthRatio;
  float tailLengthRatio = a_tailLengthRatio;
  float headWidthFactor = EXTREMITY_WIDTH_FACTORS[headId];
  float tailWidthFactor = EXTREMITY_WIDTH_FACTORS[tailId];
  float minBodyLengthRatio = `).concat(Y(p),`;

  // Per-edge values from the frame-pass texture (read by edge index).
  // tStart/tEnd are the ungated boundary clamps: re-apply the body's extremity
  // gating here (no extremity \u2192 body runs to the node center, 0/1).
  vec4 frameClamp = readFrameTexel(u_edgeFrameTexture, u_edgeFrameTextureWidth, edgeIdx);
  float tStart           = a_tailLengthRatio > 0.0 ? frameClamp.x : 0.0;
  float tEnd             = a_headLengthRatio > 0.0 ? frameClamp.y : 1.0;
  float straightenFactor = frameClamp.z;
  float pathLength       = frameClamp.w;

  // Anti-aliasing width (~1 pixel, normalized by thickness)
  float antialiasingWidth = u_correctionRatio / webGLThickness;

  float visibleLength = pathLength * (tEnd - tStart);

  // Compute extremity lengths in world units
  float headLength = headLengthRatio * webGLThickness;
  float tailLength = tailLengthRatio * webGLThickness;
  float minBodyLength = minBodyLengthRatio * webGLThickness;

  // Handle short edges: scale down extremities if needed
  float totalNeededLength = headLength + tailLength + minBodyLength;
  float extremityScale = 1.0;
  if (totalNeededLength > visibleLength && totalNeededLength > 0.0001) {
    extremityScale = visibleLength / totalNeededLength;
    headLength *= extremityScale;
    tailLength *= extremityScale;
  }

  // Convert lengths to t-values
  float headLengthT = pathLength > 0.0001 ? headLength / pathLength : 0.0;
  float tailLengthT = pathLength > 0.0001 ? tailLength / pathLength : 0.0;

  // Zone boundaries in t-space
  float tTailEnd = tStart + tailLengthT;
  float tHeadStart = tEnd - headLengthT;

  // Ensure body has non-negative length
  if (tTailEnd > tHeadStart) {
    float mid = (tStart + tEnd) * 0.5;
    tTailEnd = mid;
    tHeadStart = mid;
  }

  // Convert to webGL units for geometry expansion
  float aaWidthWebGL = antialiasingWidth * webGLThickness;

  // Extra geometry width for picking padding (0 in visual mode)
  #ifdef PICKING_MODE
    float pickingPaddingWebGL = u_pickingPadding * u_correctionRatio;
  #else
    float pickingPaddingWebGL = 0.0;
  #endif

  // Straight-line direction and normal (for blending when straightenFactor > 0)
  vec2 straightDir = length(a_target - a_source) > 0.0001
    ? normalize(a_target - a_source) : vec2(1.0, 0.0);
  vec2 straightNormal = vec2(-straightDir.y, straightDir.x);

  // Zone-based vertex processing using path selectors
  vec2 position;
  vec2 normal;
  float t;
  float zone = a_zone;
  float zoneT = a_zoneT;
  float side = a_side;

  // Scaled extremity width factors (geometry must be at least as wide as body)
  float scaledTailWidth = max(tailWidthFactor * extremityScale, 1.0);
  float scaledHeadWidth = max(headWidthFactor * extremityScale, 1.0);

  if (zone < 0.5) {
    // TAIL ZONE: rectangular quad with scaled width
    vec2 tang = queryPathTangent(pathId, tTailEnd, a_source, a_target);
    normal = vec2(-tang.y, tang.x);
    vec2 centerPos = mix(queryPathPosition(pathId, tStart, a_source, a_target),
                         queryPathPosition(pathId, tTailEnd, a_source, a_target), zoneT);
    float halfWidth = webGLThickness * scaledTailWidth * 0.5 + aaWidthWebGL + pickingPaddingWebGL;
    position = centerPos + normal * side * halfWidth;
    t = mix(tStart, tTailEnd, zoneT);

  } else if (zone < 1.5) {
    // BODY ZONE: follows path curvature with width = 1.0
    t = mix(tTailEnd, tHeadStart, zoneT);
    normal = queryPathNormal(pathId, t, a_source, a_target);
    float halfWidth = webGLThickness * 0.5 + aaWidthWebGL + pickingPaddingWebGL;
    position = queryPathPosition(pathId, t, a_source, a_target) + normal * side * halfWidth;

  } else {
    // HEAD ZONE: rectangular quad with scaled width
    vec2 tang = queryPathTangent(pathId, tHeadStart, a_source, a_target);
    normal = vec2(-tang.y, tang.x);
    vec2 centerPos = mix(queryPathPosition(pathId, tHeadStart, a_source, a_target),
                         queryPathPosition(pathId, tEnd, a_source, a_target), zoneT);
    float halfWidth = webGLThickness * scaledHeadWidth * 0.5 + aaWidthWebGL + pickingPaddingWebGL;
    position = centerPos + normal * side * halfWidth;
    t = mix(tHeadStart, tEnd, zoneT);
  }

  // Blend toward straight line based on path twist in extremity zones
  if (straightenFactor > 0.001) {
    float zoneWidth = zone < 0.5 ? webGLThickness * scaledTailWidth * 0.5 + aaWidthWebGL + pickingPaddingWebGL :
                      zone < 1.5 ? webGLThickness * 0.5 + aaWidthWebGL + pickingPaddingWebGL :
                      webGLThickness * scaledHeadWidth * 0.5 + aaWidthWebGL + pickingPaddingWebGL;
    vec2 straightPos = mix(a_source, a_target, t) + straightNormal * side * zoneWidth;
    position = mix(position, straightPos, straightenFactor);
  }

  gl_Position = vec4((u_matrix * vec3(position, 1.0)).xy, 0.0, 1.0);

  // Pass varyings to fragment shader
  v_color = a_color;
  v_color.a *= bias;
  v_opacity = a_opacity;
  v_id = a_id;
  v_thickness = webGLThickness;
  v_t = t;
  v_tStart = tStart;
  v_tEnd = tEnd;
  v_side = side;
  v_antialiasingWidth = antialiasingWidth;
  v_source = a_source;
  v_target = a_target;
  v_edgeLength = pathLength;

  // Zone varyings
  v_zone = zone;
  v_zoneT = zoneT;
  v_headLengthRatio = headLengthRatio * extremityScale;
  v_tailLengthRatio = tailLengthRatio * extremityScale;
  // Scale extremity width proportionally with length when crushed
  v_headWidthRatio = headWidthFactor * extremityScale;
  v_tailWidthRatio = tailWidthFactor * extremityScale;

  // Multi-path varyings
  v_pathId = pathId;
  v_headId = headId;
  v_tailId = tailId;
}
`);return b}function fl(n,a,t,e){var r=fe([].concat(H(n),H(t))),i=en(r),o=new Set(["u_matrix","u_sizeRatio","u_correctionRatio","u_zoomRatio","u_pixelRatio","u_cameraAngle","u_minEdgeThickness","u_pickingPadding"]),s=new Set,l=[],u=function(m){!o.has(m.name)&&!s.has(m.name)&&(s.add(m.name),l.push("uniform ".concat(m.type," ").concat(m.name,";")))};n.forEach(function(h){return h.uniforms.forEach(u)}),a.forEach(function(h){return h.uniforms.forEach(u)}),t.forEach(function(h){return h.uniforms.forEach(u)});var d=a.map(function(h){var m;return Y((m=h.baseRatio)!==null&&m!==void 0?m:.5)}).join(", "),c=function(m){var x,y;return a.length>1?"EXTREMITY_BASE_RATIOS[".concat(m,"]"):Y((x=(y=a[0])===null||y===void 0?void 0:y.baseRatio)!==null&&x!==void 0?x:.5)},p=a.some(function(h){return oe(h.length)?!0:h.length>0}),v=t.some(function(h){return h.needsNodeColors}),f=n.some(function(h){return h.needsNodeSize}),b=t.map(function(h,m){return"  // Layer ".concat(m+1,": ").concat(h.name,`
  color = blendOver(color, layer_`).concat(h.name,"(context));")}).join(`

`),g=`#version 300 es
precision highp float;

// Standard varyings
in vec4 v_color;
in float v_opacity;
in vec4 v_id;
in float v_thickness;       // Edge body thickness
in float v_t;
in float v_tStart;
in float v_tEnd;
in float v_side;
in float v_antialiasingWidth;  // Anti-aliasing width (normalized: u_correctionRatio / thickness)
in vec2 v_source;
in vec2 v_target;
in float v_edgeLength;
`.concat(f?`
in float v_sourceNodeSize;   // Source node size (mirrored in labels/generator.ts as plain float)
in float v_targetNodeSize;   // Target node size (mirrored in labels/generator.ts as plain float)`:"",`
`).concat(v?`
in vec4 v_sourceColor;
in vec4 v_targetColor;`:"",`
// Zone varyings
in float v_zone;            // 0=tail, 1=body, 2=head
in float v_zoneT;           // Position within zone [0,1]
in float v_headLengthRatio; // Head length as ratio of thickness (scaled for short edges)
in float v_tailLengthRatio; // Tail length as ratio of thickness (scaled for short edges)
in float v_headWidthRatio;  // Head width factor
in float v_tailWidthRatio;  // Tail width factor

// Multi-path/extremity varyings
flat in int v_pathId;
flat in int v_headId;
flat in int v_tailId;

// Path/layer attribute varyings (from vertex shader texture fetch)
`).concat(i.fragmentVaryingDeclarations,`

// Standard uniforms (needed by some path types)
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_cameraAngle;
#ifdef PICKING_MODE
uniform float u_pickingPadding;
#endif

// Custom uniforms
`).concat(l.join(`
`),`

// Fragment output (single target - picking handled via separate pass)
out vec4 fragColor;

`).concat(a.length>1?`// Base ratio array for extremities (shared pool for head/tail)
const float EXTREMITY_BASE_RATIOS[`.concat(a.length,"] = float[](").concat(d,");"):"",`

// EdgeContext struct
struct EdgeContext {
  float t;                   // Position along path [0, 1]
  float sdf;                 // Signed distance from centerline
  vec2 position;             // World position
  vec2 tangent;              // Path tangent
  vec2 normal;               // Path normal
  float thickness;           // Edge thickness
  float aaWidth;             // Anti-aliasing width
  float edgeLength;          // Total path length
  float tStart;              // Clamped start t
  float tEnd;                // Clamped end t
  float distanceFromSource;  // Arc distance from source
  float distanceToTarget;    // Arc distance to target
};

EdgeContext context;

// Alpha "over" compositing for layer blending
vec4 blendOver(vec4 bg, vec4 fg) {
  float a = fg.a;
  return vec4(mix(bg.rgb, fg.rgb, a), bg.a + a * (1.0 - bg.a));
}

// All path functions
`).concat(dr(n),`

// Path selector functions
`).concat(cr(n),`

// All extremity functions
`).concat(il(a),`

// Extremity SDF selector (shared pool for head/tail)
`).concat(ll(a),`

// Layer functions
`).concat(t.map(function(h){return h.glsl}).join(`

`),`

// Helper: Compute arc length using path selector
float computeArcLengthMulti(int pathId, float t0, float t1, vec2 source, vec2 target, int samples) {
  float arcLen = 0.0;
  vec2 prev = queryPathPosition(pathId, t0, source, target);
  for (int i = 1; i <= samples; i++) {
    float t = t0 + (t1 - t0) * float(i) / float(samples);
    vec2 curr = queryPathPosition(pathId, t, source, target);
    arcLen += length(curr - prev);
    prev = curr;
  }
  return arcLen;
}

void main() {
  // Compute normalized t within visible edge (0 = start, 1 = end)
  float tNorm = (v_t - v_tStart) / max(v_tEnd - v_tStart, 0.0001);

  // Edge body half-thickness
  float halfThickness = v_thickness * 0.5;

  // Convert normalized AA width to webGL units (~1 pixel)
  float aaWidthWebGL = v_antialiasingWidth * v_thickness;

  // Distance from centerline based on v_side interpolation
  float zoneWidthFactor = v_zone < 0.5 ? v_tailWidthRatio :
                          v_zone < 1.5 ? 1.0 :
                          v_headWidthRatio;
  // In PICKING_MODE, inflate halfGeometryWidth to match the inflated vertex geometry
  #ifdef PICKING_MODE
    float halfGeometryWidth = halfThickness * zoneWidthFactor + aaWidthWebGL + u_pickingPadding * aaWidthWebGL;
  #else
    float halfGeometryWidth = halfThickness * zoneWidthFactor + aaWidthWebGL;
  #endif
  float distFromCenter = abs(v_side) * halfGeometryWidth;

  // Populate EdgeContext (for layer functions)
  context.t = tNorm;
  context.sdf = distFromCenter - halfThickness;
  context.position = queryPathPosition(v_pathId, v_t, v_source, v_target);
  context.tangent = queryPathTangent(v_pathId, v_t, v_source, v_target);
  context.normal = vec2(-context.tangent.y, context.tangent.x);
  context.thickness = v_thickness;
  context.aaWidth = aaWidthWebGL;
  context.edgeLength = v_edgeLength;
  context.tStart = v_tStart;
  context.tEnd = v_tEnd;

  // Compute arc distances
  float visibleLength = v_edgeLength * (v_tEnd - v_tStart);
  float pathT = v_t;
  float pathTNorm = tNorm;
`).concat(n.every(function(h){return h.linearParameterization})?`  // All paths have linear parameterization: t maps directly to arc distance
  context.distanceFromSource = pathTNorm * visibleLength;
  context.distanceToTarget = (1.0 - pathTNorm) * visibleLength;`:n.every(function(h){return!h.linearParameterization})?`  // No paths have linear parameterization: use numerical integration
  context.distanceFromSource = computeArcLengthMulti(v_pathId, v_tStart, pathT, v_source, v_target, 16);
  context.distanceToTarget = computeArcLengthMulti(v_pathId, pathT, v_tEnd, v_source, v_target, 16);`:`  // Mixed parameterization: use analytical for linear paths, numerical for others
  if (`.concat(n.filter(function(h){return h.linearParameterization}).map(function(h){return"v_pathId == ".concat(n.indexOf(h))}).join(" || "),`) {
    context.distanceFromSource = pathTNorm * visibleLength;
    context.distanceToTarget = (1.0 - pathTNorm) * visibleLength;
  } else {
    context.distanceFromSource = computeArcLengthMulti(v_pathId, v_tStart, pathT, v_source, v_target, 16);
    context.distanceToTarget = computeArcLengthMulti(v_pathId, pathT, v_tEnd, v_source, v_target, 16);
  }`),`

  // Compute SDF based on zone using extremity selector (shared pool)
  float bodySDF = distFromCenter - halfThickness;
  float finalSDF;

`).concat(p?`  // Base ratios, from baseRatioLookup
  float headBaseRatio = `.concat(c("v_headId"),`;
  float tailBaseRatio = `).concat(c("v_tailId"),`;

  if (v_zone < 0.5) {
    // TAIL ZONE: v_zoneT goes 0 (tip) to 1 (base)
    vec2 uv = vec2((1.0 - v_zoneT) * v_tailLengthRatio, v_side * v_tailWidthRatio * 0.5);
    float tailSDF = queryExtremitySDF(v_tailId, uv, v_tailLengthRatio, v_tailWidthRatio) * v_thickness;

    // Apply union only near base (v_zoneT > 1 - baseRatio)
    if (v_zoneT > 1.0 - tailBaseRatio) {
      finalSDF = min(tailSDF, bodySDF);
    } else {
      finalSDF = tailSDF;
    }
  } else if (v_zone < 1.5) {
    // BODY ZONE: distance from centerline
    finalSDF = bodySDF;
  } else {
    // HEAD ZONE: v_zoneT goes 0 (base) to 1 (tip)
    vec2 uv = vec2(v_zoneT * v_headLengthRatio, v_side * v_headWidthRatio * 0.5);
    float headSDF = queryExtremitySDF(v_headId, uv, v_headLengthRatio, v_headWidthRatio) * v_thickness;

    // Apply union only near base (v_zoneT < baseRatio)
    if (v_zoneT < headBaseRatio) {
      finalSDF = min(headSDF, bodySDF);
    } else {
      finalSDF = headSDF;
    }
  }`):`  // No extremity draws tail/head geometry, so every vertex is body zone.
  finalSDF = bodySDF;`,`

  #ifdef PICKING_MODE
    // Picking pass: output edge ID for pixels within the picking area
    if (finalSDF > u_pickingPadding * aaWidthWebGL) discard;
    fragColor = v_id;
  #else
`).concat(e?`    // Visual pass: anti-aliased edge with layers, edge opacity applied once
    float alpha = smoothstep(aaWidthWebGL, -aaWidthWebGL, finalSDF) * v_opacity;`:`    // Visual pass: hard-edged (no anti-aliasing gradient) edge with layers, edge opacity applied once
    float alpha = (finalSDF < 0.0 ? 1.0 : 0.0) * v_opacity;`,`
    if (alpha < 0.01) discard;

    // Apply layers sequentially with "over" compositing
    vec4 color = vec4(0.0);

`).concat(b,`

    // Mix with transparent to fade both color AND alpha (pre-multiplied alpha for correct blending)
    fragColor = mix(vec4(0.0), color, alpha);
  #endif
}
`);return g}function gl(n,a,t){var e=oe(a.length)?!0:a.length>0,r=oe(t.length)?!0:t.length>0;if(n.generateConstantData){var i=n.generateConstantData();return{data:i.data,attributes:i.attributes,verticesPerEdge:i.verticesPerEdge}}return cl(n.segments,e,r)}function Mn(n){var a,t=Hi(n),e=t.paths,r=t.extremities,i=t.layers,o=(a=n.antialias)!==null&&a!==void 0?a:!0,s=new Map,l=new Map,u=new Map,d=G(e),c;try{for(d.s();!(c=d.n()).done;){var p=c.value,v=G(r),f;try{for(v.s();!(f=v.n()).done;){var b=f.value,g=G(r),h;try{for(g.s();!(h=g.n()).done;){var m=h.value,x="".concat(p.name,":").concat(b.name,":").concat(m.name),y=gl(p,b,m);s.set(x,y.verticesPerEdge),l.set(x,y.data);var _=G(y.attributes),T;try{for(_.s();!(T=_.n()).done;){var R=T.value;u.has(R.name)||u.set(R.name,R)}}catch(V){_.e(V)}finally{_.f()}}}catch(V){g.e(V)}finally{g.f()}}}catch(V){v.e(V)}finally{v.f()}}}catch(V){d.e(V)}finally{d.f()}var E=Array.from(u.values()),D={};E.forEach(function(V,K){D[V.name]=K});var P=0,w="",A=G(s),F;try{for(A.s();!(F=A.n()).done;){var L=Z(F.value,2),k=L[0],N=L[1];N>P&&(P=N,w=k)}}catch(V){A.e(V)}finally{A.f()}var z=l.get(w)||[],I=w.split(":"),C=Z(I,1),M=C[0],W=e.find(function(V){return V.name===M}),B=[];W!=null&&W.generateConstantData?B=W.generateConstantData().attributes:B=[{name:"a_zone"},{name:"a_zoneT"},{name:"a_side"}];var U=z.map(function(V){var K=new Array(E.length).fill(0);return B.forEach(function(ee,ce){var ge=D[ee.name];ge!==void 0&&ce<V.length&&(K[ge]=V[ce])}),K});return{vertexShader:hl(e,r,i,E),fragmentShader:fl(e,r,i,o),uniforms:rl(e,r,i),attributes:vl(),verticesPerEdge:P,constantData:U,constantAttributes:E,vertexCountsPerCombination:s,constantDataPerCombination:l}}function vl(n,a,t){return[{name:"a_edgeIndex",size:1,type:jt},{name:"a_color",size:4,type:Ai,normalized:!0},{name:"a_id",size:4,type:Ai,normalized:!0},{name:"a_opacity",size:1,type:jt}]}var ml=`#version 300 es
precision highp float;

in vec4 v_clamp;

// RGBA32F target: stores (tStart, tEnd, straightenFactor, pathLength).
out vec4 fragColor;

void main() {
  fragColor = v_clamp;
}
`,hr=(function(){function n(a,t){X(this,n),S(this,"uniformLocations",{});var e=t.paths,r=t.extremities,i=t.layers,o=t.nodeShapes,s=t.nodeLayers;this.gl=a,this.hasAttributeData=fe([].concat(H(e),H(i))).floatsPerItem>0,this.hasNodeAttributeData=Object.keys(Tt(o,s).offsets).length>0,this.vertexShader=qt(a,dl(e,r,i,o,s)),this.fragmentShader=Yt(a,ml),this.program=Kt(a,[this.vertexShader,this.fragmentShader]);var l=new Set;this.customUniforms=[];for(var u=0,d=[].concat(H(e),H(r));u<d.length;u++){var c=d[u],p=G(c.uniforms),v;try{for(p.s();!(v=p.n()).done;){var f=v.value;l.has(f.name)||(l.add(f.name),this.customUniforms.push(f))}}catch(x){p.e(x)}finally{p.f()}}var b=["u_sizeRatio","u_correctionRatio","u_cameraAngle","u_minEdgeThickness","u_nodeDataTexture","u_nodeDataTextureWidth","u_edgeDataTexture","u_edgeDataTextureWidth","u_edgeAttributeTexture","u_edgeAttributeTextureWidth","u_edgeAttributeTexelsPerEdge","u_layerAttributeTexture","u_layerAttributeTextureWidth","u_layerAttributeTexelsPerNode","u_frameTextureWidth","u_frameTextureHeight"].concat(H(this.customUniforms.map(function(x){return x.name}))),g=G(b),h;try{for(g.s();!(h=g.n()).done;){var m=h.value;this.uniformLocations[m]=a.getUniformLocation(this.program,m)}}catch(x){g.e(x)}finally{g.f()}this.vao=a.createVertexArray()}return j(n,[{key:"run",value:function(t,e,r,i,o){if(r!==0){var s=this.gl,l=this.uniformLocations;s.useProgram(this.program),s.bindVertexArray(this.vao),l.u_sizeRatio&&s.uniform1f(l.u_sizeRatio,t.sizeRatio),l.u_correctionRatio&&s.uniform1f(l.u_correctionRatio,t.correctionRatio),l.u_cameraAngle&&s.uniform1f(l.u_cameraAngle,t.cameraAngle),l.u_minEdgeThickness&&s.uniform1f(l.u_minEdgeThickness,t.minEdgeThickness),l.u_nodeDataTexture&&s.uniform1i(l.u_nodeDataTexture,t.nodeDataTextureUnit),l.u_nodeDataTextureWidth&&s.uniform1i(l.u_nodeDataTextureWidth,t.nodeDataTextureWidth),l.u_edgeDataTexture&&s.uniform1i(l.u_edgeDataTexture,t.edgeDataTextureUnit),l.u_edgeDataTextureWidth&&s.uniform1i(l.u_edgeDataTextureWidth,t.edgeDataTextureWidth),l.u_frameTextureWidth&&s.uniform1f(l.u_frameTextureWidth,e.getTextureWidth()),l.u_frameTextureHeight&&s.uniform1f(l.u_frameTextureHeight,e.getTextureHeight()),this.hasAttributeData&&i&&(i.bind(Ge),l.u_edgeAttributeTexture&&s.uniform1i(l.u_edgeAttributeTexture,Ge),l.u_edgeAttributeTextureWidth&&s.uniform1i(l.u_edgeAttributeTextureWidth,i.getTextureWidth()),l.u_edgeAttributeTexelsPerEdge&&s.uniform1i(l.u_edgeAttributeTexelsPerEdge,i.getTexelsPerItem())),this.hasNodeAttributeData&&o&&(o.bind(Me),l.u_layerAttributeTexture&&s.uniform1i(l.u_layerAttributeTexture,Me),l.u_layerAttributeTextureWidth&&s.uniform1i(l.u_layerAttributeTextureWidth,o.getTextureWidth()),l.u_layerAttributeTexelsPerNode&&s.uniform1i(l.u_layerAttributeTexelsPerNode,o.getTexelsPerItem()));var u=G(this.customUniforms),d;try{for(u.s();!(d=u.n()).done;){var c=d.value;Ya(s,this.uniformLocations[c.name],c)}}catch(p){u.e(p)}finally{u.f()}e.bindAsRenderTarget(),s.disable(s.BLEND),s.disable(s.DEPTH_TEST),s.drawArrays(s.POINTS,0,r),s.bindFramebuffer(s.FRAMEBUFFER,null),s.bindVertexArray(null)}}},{key:"kill",value:function(){var t=this.gl;t.deleteProgram(this.program),t.deleteShader(this.vertexShader),t.deleteShader(this.fragmentShader),t.deleteVertexArray(this.vao)}}])})();function Ht(n,a,t,e,r,i){if(n.length===1)return"".concat(e," ").concat(a,"(int pathId, ").concat(r,`) {
  return path_`).concat(n[0].name,"_").concat(t,"(").concat(i,`);
}`);var o=n.map(function(s,l){return"    case ".concat(l,": return path_").concat(s.name,"_").concat(t,"(").concat(i,");")}).join(`
`);return"".concat(e," ").concat(a,"(int pathId, ").concat(r,`) {
  switch (pathId) {
`).concat(o,`
    default: return path_`).concat(n[0].name,"_").concat(t,"(").concat(i,`);
  }
}`)}var pl=`
vec3 computeEdgeLabelBodyBounds(
  float tStart, float tEnd, float pathLength,
  float webGLThickness, float headLengthRatio, float tailLengthRatio
) {
  float visibleLength = pathLength * (tEnd - tStart);

  float headLength = headLengthRatio * webGLThickness;
  float tailLength = tailLengthRatio * webGLThickness;
  float totalNeededLength = headLength + tailLength;
  if (totalNeededLength > visibleLength && totalNeededLength > 0.0001) {
    float extremityScale = visibleLength / totalNeededLength;
    headLength *= extremityScale;
    tailLength *= extremityScale;
  }

  float bodyStartDist = tStart * pathLength + tailLength;
  float bodyEndDist = tEnd * pathLength - headLength;
  return vec3(bodyStartDist, bodyEndDist, max(bodyEndDist - bodyStartDist, 0.0));
}
`;function bl(n,a){var t=Y(n),e=Y(a);return`
float computeEdgeLabelAlpha(float bodyLength, float textWidthWebGL) {
  float ratio = textWidthWebGL > 0.0001 ? min(bodyLength / textWidthWebGL, 1.0) : 1.0;
  if (ratio < `.concat(t,`) return 0.0;
  if (ratio < `).concat(e,") return (ratio - ").concat(t,") / (").concat(e," - ").concat(t,`);
  return 1.0;
}
`)}var xl=`
float computeEdgeLabelPerpOffset(
  float positionMode,
  float halfThickness, float marginWebGL, float halfTextHeight,
  vec2 source, vec2 target, mat3 matrix
) {
  float magnitude = halfThickness + marginWebGL + halfTextHeight;
  if (positionMode == 1.0) return magnitude;
  if (positionMode == 2.0) return -magnitude;
  if (positionMode == 3.0) {
    vec3 sc = matrix * vec3(source, 1.0);
    vec3 tc = matrix * vec3(target, 1.0);
    return sc.x < tc.x ? magnitude : -magnitude;
  }
  return 0.0;
}
`;function Xi(n){var a=n.paths,t=n.minVisibilityThreshold,e=n.fullVisibilityThreshold,r=a.some(function(s){return s.hasSharpCorners}),i=a.map(function(s){return"// --- Path: ".concat(s.name,` ---
`).concat(s.glsl,`

// Tangent/normal functions: analytical if provided, otherwise numerical
`).concat(s.analyticalTangentGlsl||Wi(s.name),`

// Auto-generated fallbacks for any missing path functions
`).concat(Ui(s.name,s.glsl),`

// Corner skip helpers (for paths with sharp corners like step/taxi)
`).concat(s.cornerSkipGlsl||"",`
`)}).join(`
`),o=r?`// Corner function selectors (only some paths have sharp corners)
vec2 queryGetCornerTs(int pathId, vec2 source, vec2 target) {
  switch (pathId) {
`.concat(a.map(function(s,l){return s.hasSharpCorners?"    case ".concat(l,": return path_").concat(s.name,"_getCornerTs(source, target);"):"    case ".concat(l,": return vec2(-1.0, -1.0); // No corners for ").concat(s.name)}).join(`
`),`
    default: return vec2(-1.0, -1.0);
  }
}

vec2 queryGetCornerConcavity(int pathId, vec2 source, vec2 target, float perpOffset) {
  switch (pathId) {
`).concat(a.map(function(s,l){return s.hasSharpCorners?"    case ".concat(l,": return path_").concat(s.name,"_getCornerConcavity(source, target, perpOffset);"):"    case ".concat(l,": return vec2(0.0, 0.0); // No corners for ").concat(s.name)}).join(`
`),`
    default: return vec2(0.0, 0.0);
  }
}`):"";return`
// ============================================================================
// Node data fetch (geometry texel) and per-edge clamp fetch (edge-frame texture)
// ============================================================================

`.concat(me,`
`).concat(Ue,`

// ============================================================================
// Path Functions (one block per path)
// ============================================================================

`).concat(i,`

// ============================================================================
// Path Query Selectors (dispatch by pathId)
// ============================================================================

`).concat(Ht(a,"queryPathPosition","position","vec2","float t, vec2 source, vec2 target","t, source, target"),`

`).concat(Ht(a,"queryPathTangent","tangent","vec2","float t, vec2 source, vec2 target","t, source, target"),`

`).concat(Ht(a,"queryPathNormal","normal","vec2","float t, vec2 source, vec2 target","t, source, target"),`

`).concat(Ht(a,"queryPathLength","length","float","vec2 source, vec2 target","source, target"),`

`).concat(Ht(a,"queryPathTAtDistance","t_at_distance","float","float dist, vec2 source, vec2 target","dist, source, target"),`

`).concat(o,`

// ============================================================================
// Shared helpers (body bounds, alpha ramp, perpendicular offset)
// ============================================================================

`).concat(pl,`
`).concat(bl(t,e),`
`).concat(xl,`
`)}var yl=_e.fontSize,_l=new Map,ji=24,Ci=(ji+1)*2;function Tl(n){var a=n.paths,t=n.fontSizeMode,e=n.headLengthRatio,r=n.tailLengthRatio,i=n.minVisibilityThreshold,o=n.fullVisibilityThreshold,s=t==="scaled",l=Ee(),u=fe([].concat(H(a),[l])),d=en(u),c=`#version 300 es

// Per-instance attributes
in float a_edgeIndex;
in float a_edgeAttrIndex;
in float a_baseFontSize;
in float a_totalTextWidth;
in float a_positionMode;
in float a_margin;
in float a_padding;
in vec4 a_color;
in vec4 a_id;

// Per-vertex (constant) attribute: strip vertex index
in float a_vertexIndex;

uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_pixelRatio;
uniform float u_cameraAngle;
uniform vec2 u_resolution;
uniform sampler2D u_nodeDataTexture;
uniform int u_nodeDataTextureWidth;
uniform sampler2D u_edgeDataTexture;
uniform int u_edgeDataTextureWidth;
uniform sampler2D u_edgeFrameTexture; // Per-edge clamp (tStart, tEnd, straightenFactor, pathLength)
uniform int u_edgeFrameTextureWidth;
`.concat(s?"uniform float u_zoomSizeRatio;":"",`

`).concat(d.uniformDeclarations,`

out vec4 v_color;
out vec4 v_id;
out float v_alphaModifier;

const float ATLAS_FONT_SIZE = `).concat(Y(yl),`;
const float HEAD_RATIO = `).concat(Y(e),`;
const float TAIL_RATIO = `).concat(Y(r),`;
const int RIBBON_SEGMENTS = `).concat(ji,`;

// Path attribute varyings (declared as plain locals since this shader has no FS inputs for them)
`).concat(d.vertexVaryingDeclarations.replace(/out /g,""),`

// Node size variables used by some path functions (self-loops, etc.)
float v_sourceNodeSize;
float v_targetNodeSize;

// Shared preamble: shape SDFs, path functions + selectors, clamp, helpers.
`).concat(Xi({paths:a,minVisibilityThreshold:i,fullVisibilityThreshold:o}),`

void main() {
  int vIdx = int(a_vertexIndex);
  int pairIdx = vIdx / 2;
  int side = vIdx - pairIdx * 2; // 0 = left/bottom, 1 = right/top

  // --- Fetch edge data (2 texels per edge) ---
  int edgeIdx = int(a_edgeIndex);
  int texel0Idx = edgeIdx * 2;
  int texel1Idx = edgeIdx * 2 + 1;
  ivec2 e0 = ivec2(texel0Idx % u_edgeDataTextureWidth, texel0Idx / u_edgeDataTextureWidth);
  ivec2 e1 = ivec2(texel1Idx % u_edgeDataTextureWidth, texel1Idx / u_edgeDataTextureWidth);
  vec4 edgeData0 = texelFetch(u_edgeDataTexture, e0, 0);
  vec4 edgeData1 = texelFetch(u_edgeDataTexture, e1, 0);

  int srcIdx = int(edgeData0.x);
  int tgtIdx = int(edgeData0.y);
  float thickness = edgeData0.z;
  int pathId = int(edgeData1.z);

  // --- Fetch path attributes (curvature, etc.) ---
  {
    int edgeIdx = int(a_edgeAttrIndex);
`).concat(d.fetchCode,`
`).concat(d.varyingAssignments,`
  }

  // --- Fetch node data: geometry (texel 0) + rotation flags (texel 1) ---
  vec4 srcN = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx);
  vec4 tgtN = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx);

  vec2 source = srcN.xy;
  vec2 target = tgtN.xy;
  float sourceSize = srcN.z;
  float targetSize = tgtN.z;
  v_sourceNodeSize = sourceSize;
  v_targetNodeSize = targetSize;

  // --- Pixel-to-graph conversion (fixed font mode) ---
  float matrixScaleX = length(vec2(u_matrix[0][0], u_matrix[1][0]));
  float pixelToGraph = 2.0 / (matrixScaleX * u_resolution.x);

  float webGLThickness = thickness * u_correctionRatio / u_sizeRatio;

  // --- Body bounds (shared with edge label shader) ---
  vec4 edgeClamp = readFrameTexel(u_edgeFrameTexture, u_edgeFrameTextureWidth, edgeIdx);
  vec3 bodyBounds = computeEdgeLabelBodyBounds(
    edgeClamp.x, edgeClamp.y, edgeClamp.w,
    webGLThickness, HEAD_RATIO, TAIL_RATIO
  );
  float bodyStartDist = bodyBounds.x;
  float bodyEndDist = bodyBounds.y;
  float bodyLength = bodyBounds.z;

  // --- Text dimensions ---
  float baseFontSize = a_baseFontSize;
  `).concat(s?`float fontScale = baseFontSize / ATLAS_FONT_SIZE * u_zoomSizeRatio;
  float textWidthWebGL = a_totalTextWidth * fontScale * u_correctionRatio / u_sizeRatio;
  float halfTextHeight = baseFontSize * 0.35 * u_zoomSizeRatio * u_correctionRatio / u_sizeRatio;
  float marginWebGL = a_margin * u_zoomSizeRatio * u_correctionRatio / u_sizeRatio;`:`float fontScale = baseFontSize / ATLAS_FONT_SIZE;
  float textWidthWebGL = a_totalTextWidth * fontScale * pixelToGraph;
  float halfTextHeight = baseFontSize * 0.35 * pixelToGraph;
  float marginWebGL = a_margin * pixelToGraph;`,`
  float paddingWebGL = a_padding * pixelToGraph;

  // --- Alpha modifier (shared with edge label shader) ---
  float alphaModifier = computeEdgeLabelAlpha(bodyLength, textWidthWebGL);
  if (alphaModifier <= 0.0 || textWidthWebGL <= 0.0) {
    gl_Position = vec4(2.0, 0.0, 0.0, 1.0);
    v_color = vec4(0.0);
    v_id = vec4(0.0);
    v_alphaModifier = 0.0;
    return;
  }

  // --- Perpendicular offset (shared with edge label shader) ---
  float halfThickness = webGLThickness * 0.5;
  float perpOffset = computeEdgeLabelPerpOffset(
    a_positionMode, halfThickness, marginWebGL, halfTextHeight, source, target, u_matrix
  );

  // --- Ribbon span (clipped to body) ---
  float bodyCenterDist = (bodyStartDist + bodyEndDist) * 0.5;
  float halfTextWebGL = textWidthWebGL * 0.5;
  float labelStartDist = max(bodyCenterDist - halfTextWebGL, bodyStartDist);
  float labelEndDist = min(bodyCenterDist + halfTextWebGL, bodyEndDist);

  // Sample centerline at this pair, then apply perpendicular offset.
  // The ribbon follows the centerline path (simple & robust); for curved edges
  // this closely matches the offset path the characters sit on.
  float u = float(pairIdx) / float(RIBBON_SEGMENTS);
  float arcDist = mix(labelStartDist, labelEndDist, u);
  float t = queryPathTAtDistance(pathId, arcDist, source, target);
  vec2 pos = queryPathPosition(pathId, t, source, target);
  vec2 tan = queryPathTangent(pathId, t, source, target);
  vec2 perp = vec2(-tan.y, tan.x);

  vec2 centerPos = pos + perp * perpOffset;

  float halfRibbon = halfTextHeight + paddingWebGL;
  float sideSign = side == 0 ? -1.0 : 1.0;
  vec2 ribbonPos = centerPos + perp * (sideSign * halfRibbon);

  vec3 clipPos = u_matrix * vec3(ribbonPos, 1.0);
  gl_Position = vec4(clipPos.xy, 0.0, 1.0);

  v_color = a_color;
  v_id = a_id;
  v_alphaModifier = alphaModifier;
}
`);return c}var Sl=`#version 300 es
precision highp float;

in vec4 v_color;
in vec4 v_id;
in float v_alphaModifier;

out vec4 fragColor;

void main() {
#ifdef PICKING_MODE
  if (v_alphaModifier <= 0.0) discard;
  fragColor = v_id;
#else
  float alpha = v_color.a * v_alphaModifier;
  if (alpha <= 0.0) discard;
  fragColor = vec4(v_color.rgb * alpha, alpha);
#endif
}
`;function fr(n,a,t,e){var r=e.shaderConfig,i=r.paths,o=r.fontSizeMode;if(i.length===0)throw new Error("createEdgeLabelBackgroundProgram: shaderConfig must declare at least one path");var s=Ee(),l=fe([].concat(H(i),[s])),u=Hn([].concat(H(i),[s]),l),d=Tl(r),c=(function(p){function v(f,b,g){var h;return X(this,v),h=Q(this,v,[f,b,g]),S(h,"totalCount",0),S(h,"bufferCapacity",0),S(h,"edgeAttributeTexture",null),h.edgeAttributeTexture=new Un(f,l),h.packedAttributeData=new Float32Array(l.floatsPerItem),h}return J(v,p),j(v,[{key:"getDefinition",value:function(){for(var b=WebGL2RenderingContext,g=b.FLOAT,h=b.UNSIGNED_BYTE,m=b.TRIANGLE_STRIP,x=[],y=0;y<Ci;y++)x.push([y]);var _=["u_matrix","u_sizeRatio","u_correctionRatio","u_pixelRatio","u_cameraAngle","u_resolution","u_nodeDataTexture","u_nodeDataTextureWidth","u_edgeDataTexture","u_edgeDataTextureWidth","u_edgeFrameTexture","u_edgeFrameTextureWidth"];return o==="scaled"&&_.push("u_zoomSizeRatio"),l.floatsPerItem>0&&_.push("u_edgeAttributeTexture","u_edgeAttributeTextureWidth","u_edgeAttributeTexelsPerEdge"),{VERTICES:Ci,VERTEX_SHADER_SOURCE:d,FRAGMENT_SHADER_SOURCE:Sl,METHOD:m,UNIFORMS:_,ATTRIBUTES:[{name:"a_edgeIndex",size:1,type:g},{name:"a_edgeAttrIndex",size:1,type:g},{name:"a_baseFontSize",size:1,type:g},{name:"a_totalTextWidth",size:1,type:g},{name:"a_positionMode",size:1,type:g},{name:"a_margin",size:1,type:g},{name:"a_padding",size:1,type:g},{name:"a_color",size:4,type:h,normalized:!0},{name:"a_id",size:4,type:h,normalized:!0}],CONSTANT_ATTRIBUTES:[{name:"a_vertexIndex",size:1,type:g}],CONSTANT_DATA:x}}},{key:"processEdgeLabelBackground",value:function(b,g,h){var m=0;if(this.edgeAttributeTexture&&l.floatsPerItem>0){m=this.edgeAttributeTexture.allocate(g);var x=this.packedAttributeData;Vn(u,h.edgeAttributes,x,"",_l,0),this.edgeAttributeTexture.updateAllAttributes(g,x)}var y=this.floats,_=this.ints,T=b*this.STRIDE;y[T++]=h.edgeIndex,y[T++]=m,y[T++]=h.baseFontSize,y[T++]=h.totalTextWidth,y[T++]=h.positionMode,y[T++]=h.margin,y[T++]=h.padding,y[T++]=h.color,_[T++]=h.id}},{key:"setUniforms",value:function(b,g){var h=g.gl,m=g.uniformLocations;if(h.uniformMatrix3fv(m.u_matrix,!1,b.matrix),h.uniform1f(m.u_sizeRatio,b.sizeRatio),h.uniform1f(m.u_correctionRatio,b.correctionRatio),h.uniform1f(m.u_pixelRatio,b.pixelRatio),h.uniform1f(m.u_cameraAngle,b.cameraAngle),h.uniform2f(m.u_resolution,b.width,b.height),m.u_nodeDataTexture!==void 0&&h.uniform1i(m.u_nodeDataTexture,b.nodeDataTextureUnit),m.u_nodeDataTextureWidth!==void 0&&h.uniform1i(m.u_nodeDataTextureWidth,b.nodeDataTextureWidth),m.u_edgeDataTexture!==void 0&&h.uniform1i(m.u_edgeDataTexture,b.edgeDataTextureUnit),m.u_edgeDataTextureWidth!==void 0&&h.uniform1i(m.u_edgeDataTextureWidth,b.edgeDataTextureWidth),m.u_edgeFrameTexture!==void 0&&h.uniform1i(m.u_edgeFrameTexture,b.edgeFrameTextureUnit),m.u_edgeFrameTextureWidth!==void 0&&h.uniform1i(m.u_edgeFrameTextureWidth,b.edgeFrameTextureWidth),o==="scaled"&&m.u_zoomSizeRatio!==void 0){var x=this.renderer.getSetting("zoomToSizeRatioFunction");h.uniform1f(m.u_zoomSizeRatio,1/x(b.zoomRatio))}this.edgeAttributeTexture&&l.floatsPerItem>0&&m.u_edgeAttributeTexture!==void 0&&(this.edgeAttributeTexture.bind(Ge),h.uniform1i(m.u_edgeAttributeTexture,Ge),h.uniform1i(m.u_edgeAttributeTextureWidth,this.edgeAttributeTexture.getTextureWidth()),h.uniform1i(m.u_edgeAttributeTexelsPerEdge,this.edgeAttributeTexture.getTexelsPerItem()))}},{key:"renderProgram",value:function(b,g){this.edgeAttributeTexture&&l.floatsPerItem>0&&this.edgeAttributeTexture.upload(),te(v,"renderProgram",this,3)([b,g])}},{key:"kill",value:function(){this.edgeAttributeTexture&&(this.edgeAttributeTexture.kill(),this.edgeAttributeTexture=null),te(v,"kill",this,3)([])}},{key:"drawWebGL",value:function(b,g){var h=g.gl;this.totalCount!==0&&h.drawArraysInstanced(h.TRIANGLE_STRIP,0,this.VERTICES,this.totalCount)}},{key:"reallocate",value:function(b){this.totalCount=b,b>this.bufferCapacity&&(this.bufferCapacity=Math.max(b,Math.ceil(this.bufferCapacity*1.5)||10),te(v,"reallocate",this,3)([this.bufferCapacity]))}}])})(Pe);return new c(n,a,t)}function qi(n){var a,t,e,r,i;return{paths:n.paths,headLengthRatio:(a=n.headLengthRatio)!==null&&a!==void 0?a:0,tailLengthRatio:(t=n.tailLengthRatio)!==null&&t!==void 0?t:0,fontSizeMode:(e=n.fontSizeMode)!==null&&e!==void 0?e:"fixed",minVisibilityThreshold:(r=n.minVisibilityThreshold)!==null&&r!==void 0?r:.7,fullVisibilityThreshold:(i=n.fullVisibilityThreshold)!==null&&i!==void 0?i:.8}}var El=_e.fontSize,Rl=17/64;function Al(n){var a=n.paths,t=n.hasBorder,e=t===void 0?!1:t,r=n.fontSizeMode,i=r===void 0?"fixed":r,o=n.minVisibilityThreshold,s=o===void 0?.5:o,l=n.fullVisibilityThreshold,u=l===void 0?.6:l,d=i==="scaled",c=a.some(function(g){return g.hasSharpCorners}),p=Ee(),v=fe([].concat(H(a),[p])),f=en(v),b=`#version 300 es

// ============================================================================
// Attributes - Per Character (Instanced)
// ============================================================================

// Edge geometry: indices for texture lookup
// Edge data (source/target node indices, thickness, head/tail ratios) is fetched from edge data texture
// Edge path attributes (curvature, etc.) are fetched from edge attribute texture
in float a_edgeIndex;       // Index into edge data texture
in float a_edgeAttrIndex;   // Index into edge attribute texture (for curvature, etc.)
in float a_baseFontSize;    // Base font size in pixels (per-label)

// Character metrics (in glyph units = atlas font size pixels)
in vec4 a_charMetrics;      // (charTextOffset, charAdvance, totalTextWidth, positionMode)
in vec4 a_charDims;         // (charSize.x, charSize.y, charOffset.x, charOffset.y)

// Atlas texture coordinates
in vec4 a_texCoords;        // (x, y, width, height) in atlas pixels

// Label parameters
in vec2 a_labelParams;      // (margin, unused)

// Appearance
in vec4 a_color;            // Character color (RGBA, normalized)
`.concat(e?"in vec4 a_borderColor;      // Border color (RGBA, normalized)":"",`

// ============================================================================
// Attributes - Per Vertex (Constant)
// ============================================================================

in vec2 a_quadCorner;       // Quad corner: (0,0), (1,0), (0,1), (1,1)

// ============================================================================
// Uniforms
// ============================================================================

uniform mat3 u_matrix;
uniform float u_sizeRatio;
uniform float u_correctionRatio;
uniform float u_pixelRatio;
uniform float u_cameraAngle;    // Required by node shape SDFs
// u_sdfBufferPixels kept for ABI compatibility but unused in shader
uniform float u_sdfBufferPixels;
uniform vec2 u_resolution;
uniform vec2 u_atlasSize;
uniform sampler2D u_nodeDataTexture; // Shared texture with node position/size/shape data
uniform int u_nodeDataTextureWidth;  // Width of 2D node data texture for coordinate calculation
uniform sampler2D u_edgeDataTexture; // Shared texture with edge data
uniform int u_edgeDataTextureWidth;  // Width of 2D edge data texture for coordinate calculation
uniform sampler2D u_edgeFrameTexture; // Per-edge clamp (tStart, tEnd, straightenFactor, pathLength)
uniform int u_edgeFrameTextureWidth;
`).concat(d?"uniform float u_zoomSizeRatio;  // Zoom-based size ratio from zoomToSizeRatioFunction":"",`

// Edge path attribute texture uniforms (for curvature and other path attributes)
`).concat(f.uniformDeclarations,`

// ============================================================================
// Varyings
// ============================================================================

out vec2 v_texCoord;
out vec4 v_color;
`).concat(e?"out vec4 v_borderColor;":"",`
out float v_edgeFade;  // 0 = fully visible, 1 = fully faded (outside body)
out float v_alphaModifier;  // 0-1 based on label visibility ratio
out float v_fontScale;  // Ratio of rendered font size to atlas font size
`).concat(e?"out float v_positionMode;  // Position mode for conditional border (0=over needs border)":"",`

// ============================================================================
// Constants
// ============================================================================

const float bias = 255.0 / 254.0;
const float FADE_WIDTH_PIXELS = 15.0;  // Width of fade gradient in pixels
const float ATLAS_FONT_SIZE = `).concat(Y(El),`;  // Base font size used in SDF atlas
const float VERTICAL_CENTER_RATIO = `).concat(Y(Rl),`;  // Baseline to visual center ratio

// ============================================================================
// Path Attribute Variables (set in main, used by path functions)
// ============================================================================
// Path attributes are fetched from the edge attribute texture and stored in
// variables with v_ prefix (e.g., v_curvature) for path functions to access.
`).concat(f.vertexVaryingDeclarations.replace(/out /g,""),`

// Node size variables (set in main, used by some path functions like loops).
// These mirror the v_sourceNodeSize / v_targetNodeSize varyings in generator.ts,
// but are plain floats here since the label shader is vertex-only.
float v_sourceNodeSize;
float v_targetNodeSize;

// Shared preamble: shape SDFs, path functions + selectors, clamp, helpers.
`).concat(Xi({paths:a,minVisibilityThreshold:s,fullVisibilityThreshold:u}),`

// ============================================================================
// Main
// ============================================================================

void main() {
  // -------------------------------------------------------------------------
  // Fetch edge data from edge texture (2 texels per edge)
  // -------------------------------------------------------------------------
  // Texel 0: sourceNodeIndex, targetNodeIndex, thickness, reserved
  // Texel 1: headLengthRatio, tailLengthRatio, pathId, extremityIds
  int edgeIdx = int(a_edgeIndex);
  int texel0Idx = edgeIdx * 2;
  int texel1Idx = edgeIdx * 2 + 1;
  ivec2 edgeTexCoord0 = ivec2(texel0Idx % u_edgeDataTextureWidth, texel0Idx / u_edgeDataTextureWidth);
  ivec2 edgeTexCoord1 = ivec2(texel1Idx % u_edgeDataTextureWidth, texel1Idx / u_edgeDataTextureWidth);
  vec4 edgeData0 = texelFetch(u_edgeDataTexture, edgeTexCoord0, 0);
  vec4 edgeData1 = texelFetch(u_edgeDataTexture, edgeTexCoord1, 0);

  // Unpack edge data
  int srcIdx = int(edgeData0.x);
  int tgtIdx = int(edgeData0.y);
  float thickness = edgeData0.z;
  // edgeData0.w is reserved
  float headLengthRatio = edgeData1.x;
  float tailLengthRatio = edgeData1.y;
  int pathId = int(edgeData1.z);  // Path type for multi-path support
  float baseFontSize = a_baseFontSize;

  // -------------------------------------------------------------------------
  // Fetch path attributes from edge attribute texture
  // -------------------------------------------------------------------------
  // Note: The fetch code uses 'edgeIdx' variable, so we set it to the attribute texture index
  {
    int edgeIdx = int(a_edgeAttrIndex);  // Use attribute texture index for path attributes
`).concat(f.fetchCode,`
`).concat(f.varyingAssignments,`
  }

  // -------------------------------------------------------------------------
  // Fetch node data from node texture (geometry texel + rotation-flags texel)
  // -------------------------------------------------------------------------
  vec4 srcNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, srcIdx);
  vec4 tgtNodeData = readNodeData(u_nodeDataTexture, u_nodeDataTextureWidth, tgtIdx);

  vec2 source = srcNodeData.xy;
  vec2 target = tgtNodeData.xy;
  float sourceSize = srcNodeData.z;
  float targetSize = tgtNodeData.z;
  v_sourceNodeSize = sourceSize;
  v_targetNodeSize = targetSize;
  float charTextOffset = a_charMetrics.x;
  float charAdvance = a_charMetrics.y;
  float totalTextWidth = a_charMetrics.z;
  float positionMode = a_charMetrics.w;
  vec2 charSize = a_charDims.xy;
  vec2 charOffset = a_charDims.zw;
  float margin = a_labelParams.x;

  // -------------------------------------------------------------------------
  // Compute pixel-to-graph conversion (for fixed font size mode)
  // -------------------------------------------------------------------------
  // This converts screen pixels to graph units such that N pixels on screen
  // becomes N pixels regardless of zoom level.
  // matrixScaleX is how much the matrix scales graph units to clip space
  float matrixScaleX = length(vec2(u_matrix[0][0], u_matrix[1][0]));
  float pixelToGraph = 2.0 / (matrixScaleX * u_resolution.x);

  // -------------------------------------------------------------------------
  // Step 1: Convert thickness to WebGL units
  // -------------------------------------------------------------------------
  float webGLThickness = thickness * u_correctionRatio / u_sizeRatio;

  // -------------------------------------------------------------------------
  // Step 2: Compute body bounds (truncated at node boundaries + extremities)
  // -------------------------------------------------------------------------
  vec4 edgeClamp = readFrameTexel(u_edgeFrameTexture, u_edgeFrameTextureWidth, edgeIdx);
  vec3 bodyBounds = computeEdgeLabelBodyBounds(
    edgeClamp.x, edgeClamp.y, edgeClamp.w,
    webGLThickness, headLengthRatio, tailLengthRatio
  );
  float bodyStartDist = bodyBounds.x;
  float bodyEndDist = bodyBounds.y;
  float bodyLength = bodyBounds.z;

  // -------------------------------------------------------------------------
  // Step 3: Compute font scale and text dimensions
  // -------------------------------------------------------------------------
  // Font size modes:
  // - "fixed": Constant pixel size regardless of zoom, using pixelToGraph conversion
  // - "scaled": Scales with zoom using zoomToSizeRatioFunction
  `).concat(d?`// Scaled mode: font scales with zoom
  float fontScale = baseFontSize / ATLAS_FONT_SIZE * u_zoomSizeRatio;
  // Convert glyph-unit metrics to WebGL units (scales with zoom)
  float textWidthWebGL = totalTextWidth * fontScale * u_correctionRatio / u_sizeRatio;
  float charOffsetWebGL = charTextOffset * fontScale * u_correctionRatio / u_sizeRatio;
  float charAdvanceWebGL = charAdvance * fontScale * u_correctionRatio / u_sizeRatio;`:`// Fixed mode: font stays constant in screen pixels
  float fontScale = baseFontSize / ATLAS_FONT_SIZE;
  // Convert glyph-unit metrics to graph units using pixelToGraph (zoom-independent)
  float textWidthWebGL = totalTextWidth * fontScale * pixelToGraph;
  float charOffsetWebGL = charTextOffset * fontScale * pixelToGraph;
  float charAdvanceWebGL = charAdvance * fontScale * pixelToGraph;`,`

  // Font scale varying for fragment shader gamma scaling.
  // Ratio of rendered font size to atlas font size \u2014 used to tighten the
  // anti-aliasing band for large labels so they stay sharp.
  v_fontScale = fontScale;

  // -------------------------------------------------------------------------
  // Step 4: Alpha modifier from how much of the label fits in the body
  // -------------------------------------------------------------------------
  float alphaModifier = computeEdgeLabelAlpha(bodyLength, textWidthWebGL);

  // -------------------------------------------------------------------------
  // Step 5: Compute character center offset (truncation check moved to after curvature adjustment)
  // -------------------------------------------------------------------------
  // Character center position relative to label center (on centerline, before curvature adjustment)
  float charCenterOffset = charOffsetWebGL + charAdvanceWebGL * 0.5 - textWidthWebGL * 0.5;

  // -------------------------------------------------------------------------
  // Step 6: Compute perpendicular offset based on position mode
  // -------------------------------------------------------------------------
  // Position modes: 0=over, 1=above, 2=below, 3=auto
  // Needed early for curvature-adaptive character spacing in Step 7
  float halfThickness = webGLThickness * 0.5;
  `).concat(d?`// Scaled mode: margin and text height scale with zoom (same factor as font)
  float marginWebGL = margin * u_zoomSizeRatio * u_correctionRatio / u_sizeRatio;
  float halfTextHeight = baseFontSize * 0.35 * u_zoomSizeRatio * u_correctionRatio / u_sizeRatio;`:`// Fixed mode: margin and text height stay constant in screen pixels
  float marginWebGL = margin * pixelToGraph;
  float halfTextHeight = baseFontSize * 0.35 * pixelToGraph;`,`
  float perpOffset = computeEdgeLabelPerpOffset(
    positionMode, halfThickness, marginWebGL, halfTextHeight, source, target, u_matrix
  );

  // -------------------------------------------------------------------------
  // Step 7: Position character on path using offset path traversal
  // -------------------------------------------------------------------------
  // Body center in arc distance
  float bodyCenterDist = (bodyStartDist + bodyEndDist) * 0.5;

  // For "over" mode (perpOffset = 0), use simple centerline placement
  // For above/below modes, walk along the offset path to find correct position
  float charT;

  if (perpOffset == 0.0) {
    // Simple case: place on centerline
    float charArcDist = bodyCenterDist + charCenterOffset;
    charT = queryPathTAtDistance(pathId, charArcDist, source, target);
  } else {
    // Offset path traversal: walk along the offset curve to find character position
    // This ensures even character spacing regardless of curvature

    // Start from body center on offset path
    float centerT = queryPathTAtDistance(pathId, bodyCenterDist, source, target);

    `).concat(c?`// -----------------------------------------------------------------------
    // Corner skip setup for step/taxi edges with above/below labels
    // -----------------------------------------------------------------------
    // At concave corners (inner side of the bend), characters would bunch up
    // because the offset path has near-zero arc length. We detect corner
    // crossings during the offset path traversal and add skip distance.

    // Get corner t values and concavity
    vec2 cornerTs = queryGetCornerTs(pathId, source, target);
    vec2 concavity = queryGetCornerConcavity(pathId, source, target, perpOffset);

    // Skip distance in graph units, proportional to on-screen font size
    // For fixed mode: use pixelToGraph so gap stays constant regardless of zoom
    // For scaled mode: use the same conversion as text width
    `.concat(d?"float skipDistGraph = STEP_INNER_CORNER_SKIP_FACTOR * baseFontSize * u_zoomSizeRatio * u_correctionRatio / u_sizeRatio;":"float skipDistGraph = STEP_INNER_CORNER_SKIP_FACTOR * baseFontSize * pixelToGraph;",`

    // Corner t values for detecting crossings during traversal
    float corner1T = cornerTs.x;
    float corner2T = cornerTs.y;
    bool corner1IsConcave = concavity.x > 0.5;
    bool corner2IsConcave = concavity.y > 0.5;`):"",`

    // Target distance along offset path from center
    float targetOffsetDist = abs(charCenterOffset);

    // Handle center character (charCenterOffset \u2248 0) - no search needed
    if (targetOffsetDist < 0.0001) {
      charT = centerT;
    } else {
      vec2 centerPos = queryPathPosition(pathId, centerT, source, target);
      vec2 centerNormal = queryPathNormal(pathId, centerT, source, target);
      vec2 offsetCenter = centerPos + centerNormal * perpOffset;

      float searchDir = charCenterOffset > 0.0 ? 1.0 : -1.0;

      // Search bounds (t values for body start and end)
      float tBodyStart = queryPathTAtDistance(pathId, bodyStartDist, source, target);
      float tBodyEnd = queryPathTAtDistance(pathId, bodyEndDist, source, target);

      // Walk along offset path to find character position
      float accumDist = 0.0;
      vec2 prevOffsetPos = offsetCenter;
      float prevT = centerT;
      float foundT = centerT;

      // Search range depends on direction
      float tSearchEnd = searchDir > 0.0 ? tBodyEnd : tBodyStart;

      `).concat(c?`// Track which concave corners we've crossed to add skip distance
      bool crossedCorner1 = false;
      bool crossedCorner2 = false;
      float effectiveTargetDist = targetOffsetDist;`:"",`

      const int STEPS = 32;
      for (int i = 1; i <= STEPS; i++) {
        // Step along centerline t, from center toward target
        float stepT = centerT + searchDir * float(i) * abs(tSearchEnd - centerT) / float(STEPS);

        `).concat(c?`// Check for concave corner crossings and add skip distance
        // Corner 1 crossing check
        if (corner1IsConcave && !crossedCorner1) {
          bool crossingCorner1 = (searchDir > 0.0)
            ? (prevT < corner1T && stepT >= corner1T)
            : (prevT > corner1T && stepT <= corner1T);
          if (crossingCorner1) {
            crossedCorner1 = true;
            effectiveTargetDist += skipDistGraph;
          }
        }

        // Corner 2 crossing check
        if (corner2IsConcave && !crossedCorner2) {
          bool crossingCorner2 = (searchDir > 0.0)
            ? (prevT < corner2T && stepT >= corner2T)
            : (prevT > corner2T && stepT <= corner2T);
          if (crossingCorner2) {
            crossedCorner2 = true;
            effectiveTargetDist += skipDistGraph;
          }
        }`:"",`

        // Compute offset position at this t
        vec2 stepPos = queryPathPosition(pathId, stepT, source, target);
        vec2 stepNormal = queryPathNormal(pathId, stepT, source, target);
        vec2 offsetPos = stepPos + stepNormal * perpOffset;

        // Distance along offset path
        float segDist = length(offsetPos - prevOffsetPos);

        `).concat(c?`if (accumDist + segDist >= effectiveTargetDist) {
          // Interpolate within segment to find exact t
          float remaining = effectiveTargetDist - accumDist;
          float segT = remaining / max(segDist, 0.0001);
          foundT = mix(prevT, stepT, segT);
          break;
        }`:`if (accumDist + segDist >= targetOffsetDist) {
          // Interpolate within segment to find exact t
          float remaining = targetOffsetDist - accumDist;
          float segT = remaining / max(segDist, 0.0001);
          foundT = mix(prevT, stepT, segT);
          break;
        }`,`

        accumDist += segDist;
        prevOffsetPos = offsetPos;
        prevT = stepT;
        // Update foundT to last valid position in case loop exhausts without finding target
        foundT = stepT;
      }

      charT = foundT;
    }
  }

  // Get position and tangent at final character position
  vec2 pathPos = queryPathPosition(pathId, charT, source, target);
  vec2 tangent = queryPathTangent(pathId, charT, source, target);

  // Compute perpendicular direction (90 degrees from tangent)
  vec2 perpDir = vec2(-tangent.y, tangent.x);

  // Apply perpendicular offset to path position
  vec2 offsetPathPos = pathPos + perpDir * perpOffset;

  // -------------------------------------------------------------------------
  // Step 8: Build character quad
  // -------------------------------------------------------------------------
  // Character size in screen pixels
  vec2 charSizePixels = charSize * fontScale;

  // Character offset from origin to the atlas region's top-left corner.
  // bearingX/bearingY already include the SDF buffer.
  vec2 charOffsetPixels = charOffset * fontScale;

  // The character's local X offset from pathPos (which is at character center)
  float charLocalX = -charAdvance * 0.5 * fontScale;

  // Build quad position:
  // - Start at character origin (charLocalX on X axis, 0 on Y axis = baseline)
  // - Add bearing offset to get to atlas region corner
  // - Add quad corner * size to get vertex position
  vec2 quadPos;
  quadPos.x = charLocalX + charOffsetPixels.x + a_quadCorner.x * charSizePixels.x;
  // charOffset.y = -bearingY (negated), so -charOffsetPixels.y = bearingY * fontScale
  // (distance from baseline to atlas region top, positive = upward)
  // Quad corner (0,0) = bottom-left, (1,1) = top-right
  quadPos.y = -charOffsetPixels.y - charSizePixels.y * (1.0 - a_quadCorner.y);

  // Center vertically on the path by offsetting by half the visual text height
  // VERTICAL_CENTER_RATIO is the distance from baseline to visual center as a ratio of atlas font size
  float verticalCenterOffset = VERTICAL_CENTER_RATIO * ATLAS_FONT_SIZE * fontScale;
  quadPos.y -= verticalCenterOffset;

  // -------------------------------------------------------------------------
  // Step 9: Rotate quad to align with tangent
  // -------------------------------------------------------------------------
  // Rotation matrix from tangent
  // tangent = (cos(angle), sin(angle)), so we can build rotation directly
  mat2 rotation = mat2(tangent.x, tangent.y, -tangent.y, tangent.x);

  // Convert pixel offset to WebGL units for rotation
  `).concat(d?"vec2 quadPosWebGL = quadPos * u_correctionRatio / u_sizeRatio; // Scaled mode":"vec2 quadPosWebGL = quadPos * pixelToGraph; // Fixed mode: use pixelToGraph for zoom-independent size",`

  // Rotate around character center on path
  vec2 rotatedOffset = rotation * quadPosWebGL;

  // Final position in graph space (using offset path position for above/below modes)
  vec2 worldPos = offsetPathPos + rotatedOffset;

  // -------------------------------------------------------------------------
  // Step 10: Transform to clip space
  // -------------------------------------------------------------------------
  vec3 clipPos = u_matrix * vec3(worldPos, 1.0);
  gl_Position = vec4(clipPos.xy, 0.0, 1.0);

  // -------------------------------------------------------------------------
  // Step 11: Texture coordinates
  // -------------------------------------------------------------------------
  // Flip Y for texture coordinates (texture Y goes down, quad Y goes up)
  vec2 texCorner = vec2(a_quadCorner.x, 1.0 - a_quadCorner.y);
  v_texCoord = (a_texCoords.xy + texCorner * a_texCoords.zw) / u_atlasSize;

  // -------------------------------------------------------------------------
  // Step 12: Pass color, border color, and alpha modifier
  // -------------------------------------------------------------------------
  v_color = a_color;
  v_color.a *= bias;
`).concat(e?`  v_borderColor = a_borderColor;
  v_borderColor.a *= bias;
  v_positionMode = positionMode;`:"",`
  v_alphaModifier = alphaModifier;

  // -------------------------------------------------------------------------
  // Step 13: Compute edge fade for soft truncation
  // -------------------------------------------------------------------------
  // Convert fade width from pixels to WebGL units
  `).concat(d?"float fadeWidthWebGL = FADE_WIDTH_PIXELS * u_correctionRatio / u_sizeRatio;":"float fadeWidthWebGL = FADE_WIDTH_PIXELS * pixelToGraph;",`

  // Compute the arc position of THIS VERTEX (not just character center)
  // The quad extends from charCenter - advance/2 to charCenter + advance/2
  // a_quadCorner.x is 0 for left edge, 1 for right edge
  float vertexLocalOffset = (a_quadCorner.x - 0.5) * charAdvanceWebGL;
  float vertexArcOffset = charCenterOffset + vertexLocalOffset;

  // Compute distance from body edges (positive = inside body, negative = outside)
  float halfBody = bodyLength * 0.5;
  float distFromStart = vertexArcOffset + halfBody;  // Distance from body start edge
  float distFromEnd = halfBody - vertexArcOffset;    // Distance from body end edge
  float distFromEdge = min(distFromStart, distFromEnd);

  // Compute fade: 0 = fully visible (deep inside body), 1 = fully faded (at body edge)
  // Fade goes from 0 (at 2*fadeWidth inside) to 1 (at body edge)
  // This ensures text is fully transparent before reaching extremities
  v_edgeFade = 1.0 - smoothstep(0.0, fadeWidthWebGL * 2.0, distFromEdge);
}
`);return b}function Dl(){var n=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{},a=n.hasBorder,t=a===void 0?!1:a,e=`#version 300 es
precision highp float;

in vec2 v_texCoord;
in vec4 v_color;
`.concat(t?"in vec4 v_borderColor;":"",`
in float v_edgeFade;  // 0 = fully visible, 1 = fully faded
in float v_alphaModifier;  // 0-1 based on label visibility ratio
in float v_fontScale;  // Ratio of rendered font size to atlas font size
`).concat(t?"in float v_positionMode;  // Position mode (0=over, 1=above, 2=below, 3=auto)":"",`

uniform sampler2D u_atlas;
uniform float u_gamma;
uniform float u_sdfBuffer;
uniform float u_pixelRatio;
`).concat(t?"uniform float u_borderWidth;  // Border width in SDF units (normalized)":"",`

// Fragment output (single target - picking handled via separate pass)
out vec4 fragColor;

void main() {
  #ifdef PICKING_MODE
    // Edge labels are not pickable - discard all fragments in picking mode
    discard;
  #else
  // SDF stores normalized distance: 0.5 = on edge, >0.5 = inside glyph
  float sdfValue = texture(u_atlas, v_texCoord).a;

  // Edge threshold accounting for SDF buffer padding
  float edge = 1.0 - u_sdfBuffer;

  // Scale gamma inversely with font scale so small labels get a wider AA band
  // (smoother) and large labels get a tighter band (sharper).
  float aaWidth = u_gamma / (u_pixelRatio * v_fontScale);

  // Apply edge fade for soft truncation at body boundaries
  // Also apply visibility-based alpha modifier for short edge labels
  float edgeAlpha = (1.0 - v_edgeFade) * v_alphaModifier;

`).concat(t?`  // Fill alpha: fully opaque inside the glyph
  float fillAlpha = smoothstep(edge - aaWidth, edge + aaWidth, sdfValue);

  // Only apply border for "over" position mode (v_positionMode == 0.0)
  // Labels positioned above/below/auto don't overlap the edge line and don't need borders
  if (v_positionMode < 0.5) {
    // Border rendering: compute alpha for both fill and border regions
    // Border extends from (edge - borderWidth) to edge
    float borderEdge = edge - u_borderWidth;

    // Border alpha: opaque in the border region (between borderEdge and edge)
    float borderAlpha = smoothstep(borderEdge - aaWidth, borderEdge + aaWidth, sdfValue);

    // Composite: fill on top of border
    // Border is visible where borderAlpha > 0 but fillAlpha < 1
    vec3 borderColorPremult = v_borderColor.rgb * v_borderColor.a * borderAlpha * edgeAlpha;
    vec3 fillColorPremult = v_color.rgb * v_color.a * fillAlpha * edgeAlpha;

    // Blend fill over border (fill replaces border where fill is opaque)
    float finalBorderAlpha = borderAlpha * (1.0 - fillAlpha);
    vec3 finalColor = fillColorPremult + v_borderColor.rgb * v_borderColor.a * finalBorderAlpha * edgeAlpha;
    float finalAlpha = (v_color.a * fillAlpha + v_borderColor.a * finalBorderAlpha) * edgeAlpha;

    fragColor = vec4(finalColor, finalAlpha);
  } else {
    // No border for above/below/auto positions - simple text rendering
    float finalAlpha = v_color.a * fillAlpha * edgeAlpha;
    fragColor = vec4(v_color.rgb * finalAlpha, finalAlpha);
  }`:`  // Smooth transition from transparent to opaque at glyph edge
  float alpha = smoothstep(edge - aaWidth, edge + aaWidth, sdfValue);

  // Premultiplied alpha output
  float finalAlpha = v_color.a * alpha * edgeAlpha;
  fragColor = vec4(v_color.rgb * finalAlpha, finalAlpha);`,`
  #endif
}
`);return e}function Cl(n){var a=arguments.length>1&&arguments[1]!==void 0?arguments[1]:!1,t=arguments.length>2&&arguments[2]!==void 0?arguments[2]:"fixed",e=["u_matrix","u_sizeRatio","u_correctionRatio","u_pixelRatio","u_cameraAngle","u_sdfBufferPixels","u_resolution","u_atlasSize","u_atlas","u_gamma","u_sdfBuffer","u_nodeDataTexture","u_nodeDataTextureWidth","u_edgeDataTexture","u_edgeDataTextureWidth","u_edgeFrameTexture","u_edgeFrameTextureWidth","u_edgeAttributeTexture","u_edgeAttributeTextureWidth","u_edgeAttributeTexelsPerEdge"];t==="scaled"&&e.push("u_zoomSizeRatio"),a&&e.push("u_borderWidth");var r=G(n),i;try{for(r.s();!(i=r.n()).done;){var o=i.value,s=G(o.uniforms),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;e.includes(u.name)||e.push(u.name)}}catch(d){s.e(d)}finally{s.f()}}}catch(d){r.e(d)}finally{r.f()}return e}function gr(n){var a=n.hasBorder,t=a===void 0?!1:a,e=n.fontSizeMode,r=e===void 0?"fixed":e;return{vertexShader:Al(n),fragmentShader:Dl({hasBorder:t}),uniforms:Cl(n.paths,t,r)}}var Ll=new Map;function Pl(n){switch(n){case"over":return 0;case"above":return 1;case"below":return 2;case"auto":return 3;default:return 0}}function vr(n,a,t,e){var r=e.color,i=e.margin,o=e.textBorder,s=qi(e),l=s.paths,u=s.fontSizeMode,d=s.minVisibilityThreshold,c=s.fullVisibilityThreshold,p=!!o,v=gr({paths:l,hasBorder:p,fontSizeMode:u,minVisibilityThreshold:d,fullVisibilityThreshold:c}),f=(function(b){function g(h,m,x){var y;X(this,g),y=Q(this,g,[h,m,x]),S(y,"atlasTexture",null),S(y,"atlasNeedsUpdate",!1),S(y,"labelGlyphCache",new Map),S(y,"edgeAttributeTexture",null);var _=Ee();if(y.attributeLayout=fe([].concat(H(l),[_])),y.attrDescriptors=Hn([].concat(H(l),[_]),y.attributeLayout),y.edgeAttributeTexture=new Un(h,y.attributeLayout),y.packedAttributeData=new Float32Array(y.attributeLayout.floatsPerItem),y.atlasManager=new Ce,y.gamma=.025,y.sdfBuffer=_e.cutoff,y.atlasTexture=h.createTexture(),!y.atlasTexture)throw new Error("EdgeLabelProgram: failed to create atlas texture");h.bindTexture(h.TEXTURE_2D,y.atlasTexture),h.texParameteri(h.TEXTURE_2D,h.TEXTURE_WRAP_S,h.CLAMP_TO_EDGE),h.texParameteri(h.TEXTURE_2D,h.TEXTURE_WRAP_T,h.CLAMP_TO_EDGE),h.texParameteri(h.TEXTURE_2D,h.TEXTURE_MIN_FILTER,h.LINEAR),h.texParameteri(h.TEXTURE_2D,h.TEXTURE_MAG_FILTER,h.LINEAR),h.bindTexture(h.TEXTURE_2D,null),y.atlasManager.on(Ce.ATLAS_UPDATED_EVENT,function(){y.atlasNeedsUpdate=!0,setTimeout(function(){return y.renderer.refresh()},0)});var T={family:"sans-serif",weight:"normal",style:"normal"};return y.defaultFontKey=y.atlasManager.registerFont(T),y}return J(g,b),j(g,[{key:"getDefinition",value:function(){var m=WebGL2RenderingContext,x=m.FLOAT,y=m.UNSIGNED_BYTE,_=m.TRIANGLE_STRIP,T=new Set,R=[],E=G(l),D;try{for(E.s();!(D=E.n()).done;){var P=D.value,w=G(P.attributes),A;try{for(w.s();!(A=w.n()).done;){var F=A.value,L=F.name.startsWith("a_")?F.name:"a_".concat(F.name);T.has(L)||(T.add(L),R.push({name:L,size:F.size,type:F.type}))}}catch(k){w.e(k)}finally{w.f()}}}catch(k){E.e(k)}finally{E.f()}return{VERTICES:4,VERTEX_SHADER_SOURCE:v.vertexShader,FRAGMENT_SHADER_SOURCE:v.fragmentShader,METHOD:_,UNIFORMS:v.uniforms,ATTRIBUTES:[{name:"a_edgeIndex",size:1,type:x},{name:"a_edgeAttrIndex",size:1,type:x},{name:"a_baseFontSize",size:1,type:x},{name:"a_charMetrics",size:4,type:x},{name:"a_charDims",size:4,type:x},{name:"a_texCoords",size:4,type:x},{name:"a_labelParams",size:2,type:x},{name:"a_color",size:4,type:y,normalized:!0}].concat(H(p?[{name:"a_borderColor",size:4,type:y,normalized:!0}]:[]),H(R.filter(function(k){return!["a_curvature","curvature"].includes(k.name)}))),CONSTANT_ATTRIBUTES:[{name:"a_quadCorner",size:2,type:x}],CONSTANT_DATA:[[0,0],[1,0],[0,1],[1,1]]}}},{key:"prepareLabelGlyphs",value:function(m,x){if(x.hidden||!x.text){this.labelGlyphCache.delete(m);return}var y=x.text,_=x.fontKey||this.defaultFontKey;this.atlasManager.ensureGlyphs(y,_);var T=[],R=[],E=0,D=G(y),P;try{for(D.s();!(P=D.n()).done;){var w=P.value,A=w.codePointAt(0);if(A===void 0){T.push(void 0),R.push(E);continue}var F=this.atlasManager.getGlyph(A,_);T.push(F),R.push(E),F&&(E+=F.advance)}}catch(L){D.e(L)}finally{D.f()}this.labelGlyphCache.set(m,{glyphs:T,xOffsets:R,totalWidth:E})}},{key:"processCharacter",value:function(m,x,y,_){var T,R,E,D=this.floats,P=this.STRIDE,w=m*P,A=this.labelGlyphCache.get(x.parentKey);if(!A||!A.glyphs[_]){for(var F=0;F<P;F++)D[w+F]=0;return}var L=A.glyphs[_],k=A.xOffsets[_],N=g.labelColor,z=N&&q(N)==="object"&&"color"in N&&N.color?N.color:x.color,I=ie(z),C=w;D[C++]=x.edgeIndex,D[C++]=(T=(R=this.edgeAttributeTexture)===null||R===void 0?void 0:R.getIndex(x.parentKey))!==null&&T!==void 0?T:0,D[C++]=x.size,D[C++]=k,D[C++]=L.advance,D[C++]=A.totalWidth,D[C++]=Pl(x.position),D[C++]=L.atlasWidth,D[C++]=L.atlasHeight,D[C++]=L.bearingX,D[C++]=-L.bearingY,D[C++]=L.atlasX,D[C++]=L.atlasY,D[C++]=L.atlasWidth,D[C++]=L.atlasHeight;var M=(E=g.labelMargin)!==null&&E!==void 0?E:x.margin;if(D[C++]=M,D[C++]=0,D[C++]=I,p&&o){var W;typeof o.color=="string"?W=o.color:W=o.color.color||"#ffffff",D[C++]=ie(W)}var B=new Set,U=G(l),V;try{for(U.s();!(V=U.n()).done;){var K=V.value,ee=G(K.attributes),ce;try{for(ee.s();!(ce=ee.n()).done;){var ge=ce.value,Ct=ge.name.startsWith("a_")?ge.name.slice(2):ge.name;if(Ct!=="curvature"&&!B.has(Ct)){B.add(Ct);for(var ln=0;ln<ge.size;ln++)D[C++]=0}}}catch(it){ee.e(it)}finally{ee.f()}}}catch(it){U.e(it)}finally{U.f()}}},{key:"processEdgeLabel",value:function(m,x,y){if(this.prepareLabelGlyphs(m,y),this.edgeAttributeTexture&&!y.hidden&&y.text){this.edgeAttributeTexture.allocate(m);var _=this.packedAttributeData;Vn(this.attrDescriptors,y.edgeAttributes,_,"",Ll,0),this.edgeAttributeTexture.updateAllAttributes(m,_)}return te(g,"processLabel",this,3)([m,x,y])}},{key:"updateAtlasTexture",value:function(){if(this.atlasNeedsUpdate){var m=this.normalProgram.gl,x=this.atlasManager.getTextures();if(x.length!==0){var y=x[0];m.bindTexture(m.TEXTURE_2D,this.atlasTexture),m.texImage2D(m.TEXTURE_2D,0,m.RGBA,y.width,y.height,0,m.RGBA,m.UNSIGNED_BYTE,y.data),m.bindTexture(m.TEXTURE_2D,null),this.atlasNeedsUpdate=!1}}}},{key:"setUniforms",value:function(m,x){var y=x.gl,_=x.uniformLocations,T=this.atlasManager.getTextures(),R=T.length>0?[T[0].width,T[0].height]:[1,1];if(y.uniformMatrix3fv(_.u_matrix,!1,m.matrix),y.uniform1f(_.u_sizeRatio,m.sizeRatio),y.uniform1f(_.u_correctionRatio,m.correctionRatio),y.uniform1f(_.u_pixelRatio,m.pixelRatio),y.uniform1f(_.u_cameraAngle,m.cameraAngle),y.uniform1f(_.u_sdfBufferPixels,_e.buffer),y.uniform2f(_.u_resolution,m.width,m.height),y.uniform2f(_.u_atlasSize,R[0],R[1]),y.uniform1f(_.u_gamma,this.gamma),y.uniform1f(_.u_sdfBuffer,this.sdfBuffer),y.activeTexture(y.TEXTURE0),y.bindTexture(y.TEXTURE_2D,this.atlasTexture),y.uniform1i(_.u_atlas,0),_.u_nodeDataTexture!==void 0&&y.uniform1i(_.u_nodeDataTexture,m.nodeDataTextureUnit),_.u_nodeDataTextureWidth!==void 0&&y.uniform1i(_.u_nodeDataTextureWidth,m.nodeDataTextureWidth),_.u_edgeDataTexture!==void 0&&y.uniform1i(_.u_edgeDataTexture,m.edgeDataTextureUnit),_.u_edgeDataTextureWidth!==void 0&&y.uniform1i(_.u_edgeDataTextureWidth,m.edgeDataTextureWidth),_.u_edgeFrameTexture!==void 0&&y.uniform1i(_.u_edgeFrameTexture,m.edgeFrameTextureUnit),_.u_edgeFrameTextureWidth!==void 0&&y.uniform1i(_.u_edgeFrameTextureWidth,m.edgeFrameTextureWidth),p&&o&&_.u_borderWidth!==void 0){var E=o.width/_e.buffer*this.sdfBuffer;y.uniform1f(_.u_borderWidth,E)}if(this.edgeAttributeTexture&&_.u_edgeAttributeTexture!==void 0&&(this.edgeAttributeTexture.bind(Ge),y.uniform1i(_.u_edgeAttributeTexture,Ge),y.uniform1i(_.u_edgeAttributeTextureWidth,this.edgeAttributeTexture.getTextureWidth()),y.uniform1i(_.u_edgeAttributeTexelsPerEdge,this.edgeAttributeTexture.getTexelsPerItem())),u==="scaled"&&_.u_zoomSizeRatio!==void 0){var D=this.renderer.getSetting("zoomToSizeRatioFunction"),P=1/D(m.zoomRatio);y.uniform1f(_.u_zoomSizeRatio,P)}}},{key:"renderProgram",value:function(m,x){this.updateAtlasTexture(),this.atlasManager.hasPendingGlyphs()&&(this.atlasManager.flush(),this.updateAtlasTexture()),this.edgeAttributeTexture&&this.edgeAttributeTexture.upload(),te(g,"renderProgram",this,3)([m,x])}},{key:"registerFont",value:function(m){var x=arguments.length>1&&arguments[1]!==void 0?arguments[1]:"normal",y=arguments.length>2&&arguments[2]!==void 0?arguments[2]:"normal";return this.atlasManager.registerFont({family:m,weight:x,style:y})}},{key:"getAtlasManager",value:function(){return this.atlasManager}},{key:"ensureGlyphsReady",value:function(m,x){var y=x||this.defaultFontKey,_=G(m),T;try{for(_.s();!(T=_.n()).done;){var R=T.value;this.atlasManager.ensureGlyphs(R,y)}}catch(E){_.e(E)}finally{_.f()}this.atlasManager.flush()}},{key:"measureLabelAtlasWidth",value:function(m,x){var y=x||this.defaultFontKey;this.atlasManager.ensureGlyphs(m,y),this.atlasManager.hasPendingGlyphs()&&this.atlasManager.flush();var _=0,T=G(m),R;try{for(T.s();!(R=T.n()).done;){var E=R.value,D=E.codePointAt(0);if(D!==void 0){var P=this.atlasManager.getGlyph(D,y);P&&(_+=P.advance)}}}catch(w){T.e(w)}finally{T.f()}return _}},{key:"measureLabel",value:function(m,x,y){var _=this.measureLabelAtlasWidth(m,y),T=x/_e.fontSize;return{width:_*T,height:x,textHeight:x}}},{key:"kill",value:function(){var m=this.normalProgram.gl;this.atlasTexture&&(m.deleteTexture(this.atlasTexture),this.atlasTexture=null),this.edgeAttributeTexture&&(this.edgeAttributeTexture.kill(),this.edgeAttributeTexture=null),this.atlasManager.destroy(),this.labelGlyphCache.clear(),te(g,"kill",this,3)([])}}])})(jn);return S(f,"labelColor",r),S(f,"labelMargin",i),new f(n,a,t)}function Fl(){var n=`
// No extremity - always returns positive (outside)
float extremity_none(vec2 uv, float lengthRatio, float widthRatio) {
  return 1.0;
}
`;return{name:"none",glsl:n,length:0,widthFactor:1,margin:0,uniforms:[],attributes:[]}}function Kn(n,a,t,e,r,i,o){var s,l,u=Hi(e),d=u.paths,c=u.layers,p=u.defaultHead,v=u.defaultTail,f=[Fl()].concat(H(u.extremities)),b={},g={};d.forEach(function(F,L){return b[F.name]=L}),f.forEach(function(F,L){return g[F.name]=L});var h=(s=g[p])!==null&&s!==void 0?s:0,m=(l=g[v])!==null&&l!==void 0?l:0,x=null,y=fe([].concat(H(d),H(c))),_=(function(F){function L(k,N,z){var I;X(this,L),x||(x=Mn({paths:d,extremities:f,layers:c,antialias:r})),I=Q(this,L,[k,N,z]),S(I,"layerLifecycles",new Map),S(I,"needsShaderRegeneration",!1),S(I,"edgeAttributeTexture",null),S(I,"layout",y),S(I,"attrDescriptors",[]),S(I,"lifecycleIndexOffset",d.length),I._pickingBuffer=N,I.edgeAttributeTexture=new Un(k,I.layout),I.packedAttributeData=new Float32Array(I.layout.floatsPerItem),c.forEach(function(M,W){if(M.lifecycle){var B={gl:k,renderer:{refresh:function(){return z.refresh()}},getUniformLocation:function(V){return k.getUniformLocation(I.normalProgram.program,V)},requestShaderRegeneration:function(){I.needsShaderRegeneration=!0},requestRefresh:function(){z.refresh()}};I.layerLifecycles.set(W,M.lifecycle(B))}}),I.layerLifecycles.forEach(function(M){var W;return(W=M.init)===null||W===void 0?void 0:W.call(M)});var C=new Map;return I.layerLifecycles.forEach(function(M,W){M.getAttributeData&&C.set(d.length+W,M)}),I.attrDescriptors=Hn([].concat(H(d),H(c)),I.layout,C),I}return J(L,F),j(L,[{key:"getAttributeTexture",value:function(){return this.edgeAttributeTexture}},{key:"resolveEdgeIds",value:function(N,z,I){var C=N,M=0,W=h,B=m,U=z?C.selfLoopPath:I&&C.parallelPath?C.parallelPath:C.path;U&&b[U]!==void 0&&(M=b[U]),C.head&&C.head!=="none"&&g[C.head]!==void 0&&(W=g[C.head]),C.tail&&C.tail!=="none"&&g[C.tail]!==void 0&&(B=g[C.tail]);var V=f[W],K=f[B];return{pathId:M,headId:W,tailId:B,headLengthRatio:oe(V.length)?0:V.length,tailLengthRatio:oe(K.length)?0:K.length}}},{key:"getDefinition",value:function(){var N=WebGL2RenderingContext,z=N.TRIANGLE_STRIP,I=z,C=x;return{VERTICES:C.verticesPerEdge,VERTEX_SHADER_SOURCE:C.vertexShader,FRAGMENT_SHADER_SOURCE:C.fragmentShader,METHOD:I,UNIFORMS:C.uniforms,ATTRIBUTES:C.attributes,CONSTANT_ATTRIBUTES:C.constantAttributes,CONSTANT_DATA:C.constantData}}},{key:"maybeRegenerateShaders",value:function(){var N=this;if(this.needsShaderRegeneration){this.needsShaderRegeneration=!1;var z=c.map(function(V,K){var ee=N.layerLifecycles.get(K);return ee!=null&&ee.regenerate?ee.regenerate():V});x=Mn({paths:d,extremities:f,layers:z,antialias:this.renderer.getSetting("antialiasEdges")});var I=this.normalProgram.gl,C=this.normalProgram,M=C.program,W=C.buffer,B=C.vertexShader,U=C.fragmentShader;I.deleteProgram(M),I.deleteBuffer(W),I.deleteShader(B),I.deleteShader(U),this.normalProgram=this.getProgramInfo("normal",I,x.vertexShader,x.fragmentShader,this._pickingBuffer)}}},{key:"process",value:function(N,z,I,C,M,W){var B=z*this.STRIDE;if(M.visibility==="hidden"||I.visibility==="hidden"||C.visibility==="hidden"){for(var U=B+this.STRIDE;B<U;B++)this.floats[B]=0;this.floats[z*this.STRIDE]=Gi;return}this.processVisibleItem(Ie(N),B,I,C,M,W)}},{key:"processVisibleItem",value:function(N,z,I,C,M,W){var B,U=this.floats,V=this.ints;U[z++]=W,U[z++]=ie(M.color),V[z++]=N,U[z++]=(B=M.opacity)!==null&&B!==void 0?B:1;var K=this.packedAttributeData;Vn(this.attrDescriptors,M,K,M.color,this.layerLifecycles,this.lifecycleIndexOffset),this.edgeAttributeTexture.updateAllAttributesAtRow(W,K)}},{key:"setUniforms",value:function(N,z){var I=this,C=z.gl,M=z.uniformLocations;M.u_matrix&&C.uniformMatrix3fv(M.u_matrix,!1,N.matrix),M.u_sizeRatio&&C.uniform1f(M.u_sizeRatio,N.sizeRatio),M.u_correctionRatio&&C.uniform1f(M.u_correctionRatio,N.correctionRatio),M.u_zoomRatio&&C.uniform1f(M.u_zoomRatio,N.zoomRatio),M.u_pixelRatio&&C.uniform1f(M.u_pixelRatio,N.pixelRatio),M.u_cameraAngle&&C.uniform1f(M.u_cameraAngle,N.cameraAngle),M.u_feather&&C.uniform1f(M.u_feather,N.antiAliasingFeather),M.u_minEdgeThickness&&C.uniform1f(M.u_minEdgeThickness,N.minEdgeThickness),M.u_pickingPadding&&C.uniform1f(M.u_pickingPadding,N.edgePickingPadding),M.u_nodeDataTexture&&C.uniform1i(M.u_nodeDataTexture,N.nodeDataTextureUnit),M.u_nodeDataTextureWidth&&C.uniform1i(M.u_nodeDataTextureWidth,N.nodeDataTextureWidth),M.u_edgeDataTexture&&C.uniform1i(M.u_edgeDataTexture,N.edgeDataTextureUnit),M.u_edgeDataTextureWidth&&C.uniform1i(M.u_edgeDataTextureWidth,N.edgeDataTextureWidth),M.u_edgeFrameTexture&&C.uniform1i(M.u_edgeFrameTexture,N.edgeFrameTextureUnit),M.u_edgeFrameTextureWidth&&C.uniform1i(M.u_edgeFrameTextureWidth,N.edgeFrameTextureWidth),this.edgeAttributeTexture&&this.layout.floatsPerItem>0&&(this.edgeAttributeTexture.bind(Ge),M.u_edgeAttributeTexture&&C.uniform1i(M.u_edgeAttributeTexture,Ge),M.u_edgeAttributeTextureWidth&&C.uniform1i(M.u_edgeAttributeTextureWidth,this.edgeAttributeTexture.getTextureWidth()),M.u_edgeAttributeTexelsPerEdge&&C.uniform1i(M.u_edgeAttributeTexelsPerEdge,this.edgeAttributeTexture.getTexelsPerItem()));var W=new Set;d.forEach(function(B){B.uniforms.forEach(function(U){W.has(U.name)||(W.add(U.name),I.setTypedUniform(U,z))})}),f.forEach(function(B){B.uniforms.forEach(function(U){W.has(U.name)||(W.add(U.name),I.setTypedUniform(U,z))})}),c.forEach(function(B){B.uniforms.forEach(function(U){W.has(U.name)||(W.add(U.name),I.setTypedUniform(U,z))})})}},{key:"renderProgram",value:function(N,z){this.maybeRegenerateShaders(),this.layerLifecycles.forEach(function(I){var C;return(C=I.beforeRender)===null||C===void 0?void 0:C.call(I)}),te(L,"renderProgram",this,3)([N,z])}},{key:"uploadAttributeTexture",value:function(){this.edgeAttributeTexture&&this.layout.floatsPerItem>0&&this.edgeAttributeTexture.upload()}},{key:"kill",value:function(){this.layerLifecycles.forEach(function(N){var z;return(z=N.kill)===null||z===void 0?void 0:z.call(N)}),this.edgeAttributeTexture&&(this.edgeAttributeTexture.kill(),this.edgeAttributeTexture=null),te(L,"kill",this,3)([])}}])})(Pe),T=f[h],R=f[m],E=O({paths:d,headLengthRatio:oe(T.length)?0:T.length,tailLengthRatio:oe(R.length)?0:R.length},e.label),D=qi(E),P=vr(n,null,t,E),w=fr(n,a,t,{shaderConfig:D}),A=new hr(n,{paths:d,extremities:f,layers:c,nodeShapes:i,nodeLayers:o});return{edgeProgram:new _(n,null,t),labelProgram:P,labelBackgroundProgram:w,framePass:A}}function wl(n){return q(n)==="object"&&"uniforms"in n&&Array.isArray(n.uniforms)}function Il(n){return q(n)==="object"&&"uniforms"in n&&"attributes"in n&&"glsl"in n}function kl(n){return q(n)==="object"&&"uniforms"in n&&"attributes"in n&&"segments"in n}function zl(n){return q(n)==="object"&&"uniforms"in n&&"attributes"in n&&"length"in n}function Nl(n){return q(n)==="object"&&"uniforms"in n&&"attributes"in n&&"glsl"in n}function Ml(n){return q(n)==="object"&&"glsl"in n&&"name"in n&&!("uniforms"in n)}function Gl(n){return q(n)==="object"&&"glsl"in n&&"name"in n&&!("uniforms"in n)}function Ol(n){return q(n)==="object"&&"glsl"in n&&"name"in n&&!("uniforms"in n)}function Bl(n){if(wl(n))return n;if(Ml(n))return{name:n.name,glsl:n.glsl,inradiusFactor:n.inradiusFactor,uniforms:[]};throw new Error("Invalid node shape specification: ".concat(JSON.stringify(n)))}function Wl(n){if(Il(n))return n;if(ti(n))return{name:n.name,glsl:n.glsl,uniforms:[],attributes:[]};throw new Error("Invalid node layer specification: ".concat(JSON.stringify(n)))}function Ul(n){if(kl(n))return n;if(Gl(n))return{name:n.name,glsl:n.glsl,segments:n.segments,uniforms:[],attributes:[]};throw new Error("Invalid edge path specification: ".concat(JSON.stringify(n)))}function Hl(n){if(Nl(n))return n;if(ni(n))return{name:n.name,glsl:n.glsl,uniforms:[],attributes:[]};throw new Error("Invalid edge layer specification: ".concat(JSON.stringify(n)))}function Vl(n){if(zl(n))return n;if(Ol(n))return{name:n.name,glsl:n.glsl,length:n.length,widthFactor:n.widthFactor,margin:0,uniforms:[],attributes:[]};throw new Error("Invalid edge extremity specification: ".concat(JSON.stringify(n)))}function Yi(n){var a,t,e=(a=n?.shapes)!==null&&a!==void 0?a:It.shapes,r=(t=n?.layers)!==null&&t!==void 0?t:It.layers,i=e.map(Bl),o=r.map(Wl);if(i.length===0)throw new Error("At least one node shape must be specified.");if(o.length===0)throw new Error("At least one node layer must be specified.");return{shapes:i,layers:o}}function Xl(n){var a,t,e,r=(a=n?.paths)!==null&&a!==void 0?a:ht.paths,i=(t=n?.extremities)!==null&&t!==void 0?t:ht.extremities,o=(e=n?.layers)!==null&&e!==void 0?e:ht.layers,s=r.map(Ul),l=i.map(Vl).filter(function(d){return d!==null}),u=o.map(Hl);if(s.length===0)throw new Error("At least one edge path must be specified.");if(u.length===0)throw new Error("At least one edge layer must be specified.");return{paths:s,extremities:l,layers:u}}function Ki(n,a){var t={},e=G(n),r;try{for(e.s();!(r=e.n()).done;){var i=r.value;i.variables&&Object.assign(t,i.variables)}}catch(o){e.e(o)}finally{e.f()}return Object.assign(t,a||{}),t}function Zi(n,a,t,e,r){var i=Yi(e),o=i.shapes,s=i.layers,l=Ki(o,e?.variables),u=Yn(n,a,t,{shapes:o,layers:s,label:e?.label,backdrop:e?.backdrop,labelAttachments:e?.labelAttachments},r);return O(O({},u),{},{variables:l})}function $i(n,a,t,e,r,i){var o=Xl(e),s=o.paths,l=o.extremities,u=o.layers,d=Yi(i),c=d.shapes,p=d.layers,v=Ki(s,e?.variables),f=Kn(n,a,t,{paths:s,extremities:l,layers:u,defaultHead:e?.defaultHead,defaultTail:e?.defaultTail,label:e?.label},r,c,p);return O(O({},f),{},{variables:v,paths:s})}var jl=2;function Zn(n,a,t){var e=arguments.length>3&&arguments[3]!==void 0?arguments[3]:jl,r=a.canvas,i=r.width,o=r.height,s=t.x,l=t.y,u=t.rowHeight,d=t.maxRowWidth,c={},p=[],v=G(n),f;try{for(v.s();!(f=v.n()).done;){var b=f.value,g=b.width+e,h=b.height+e;if(g>i||h>o||s+g>i&&l+u+h>o){p.push(b);continue}s+g>i&&(d=Math.max(d,s),s=0,l+=u,u=h),b.draw(a,s,l),c[b.key]={x:s,y:l,width:b.width,height:b.height},s+=g,u=Math.max(u,h)}}catch(m){v.e(m)}finally{v.f()}return d=Math.max(d,s),{atlas:c,cursor:{x:s,y:l,rowHeight:u,maxRowWidth:d},remaining:p}}function se(n,a,t,e){var r=Object.defineProperty;try{r({},"",{})}catch{r=0}se=function(i,o,s,l){function u(d,c){se(i,d,function(p){return this._invoke(d,c,p)})}o?r?r(i,o,{value:s,enumerable:!l,configurable:!l,writable:!l}):i[o]=s:(u("next",0),u("throw",1),u("return",2))},se(n,a,t,e)}function le(){var n,a,t=typeof Symbol=="function"?Symbol:{},e=t.iterator||"@@iterator",r=t.toStringTag||"@@toStringTag";function i(v,f,b,g){var h=f&&f.prototype instanceof s?f:s,m=Object.create(h.prototype);return se(m,"_invoke",(function(x,y,_){var T,R,E,D=0,P=_||[],w=!1,A={p:0,n:0,v:n,a:F,f:F.bind(n,4),d:function(L,k){return T=L,R=0,E=n,A.n=k,o}};function F(L,k){for(R=L,E=k,a=0;!w&&D&&!N&&a<P.length;a++){var N,z=P[a],I=A.p,C=z[2];L>3?(N=C===k)&&(E=z[(R=z[4])?5:(R=3,3)],z[4]=z[5]=n):z[0]<=I&&((N=L<2&&I<z[1])?(R=0,A.v=k,A.n=z[1]):I<C&&(N=L<3||z[0]>k||k>C)&&(z[4]=L,z[5]=k,A.n=C,R=0))}if(N||L>1)return o;throw w=!0,k}return function(L,k,N){if(D>1)throw TypeError("Generator is already running");for(w&&k===1&&F(k,N),R=k,E=N;(a=R<2?n:E)||!w;){T||(R?R<3?(R>1&&(A.n=-1),F(R,E)):A.n=E:A.v=E);try{if(D=2,T){if(R||(L="next"),a=T[L]){if(!(a=a.call(T,E)))throw TypeError("iterator result is not an object");if(!a.done)return a;E=a.value,R<2&&(R=0)}else R===1&&(a=T.return)&&a.call(T),R<2&&(E=TypeError("The iterator does not provide a '"+L+"' method"),R=1);T=n}else if((a=(w=A.n<0)?E:x.call(y,A))!==o)break}catch(z){T=n,R=1,E=z}finally{D=1}}return{value:a,done:w}}})(v,b,g),!0),m}var o={};function s(){}function l(){}function u(){}a=Object.getPrototypeOf;var d=[][e]?a(a([][e]())):(se(a={},e,function(){return this}),a),c=u.prototype=s.prototype=Object.create(d);function p(v){return Object.setPrototypeOf?Object.setPrototypeOf(v,u):(v.__proto__=u,se(v,r,"GeneratorFunction")),v.prototype=Object.create(c),v}return l.prototype=u,se(c,"constructor",u),se(u,"constructor",l),l.displayName="GeneratorFunction",se(u,r,"GeneratorFunction"),se(c),se(c,r,"Generator"),se(c,e,function(){return this}),se(c,"toString",function(){return"[object Generator]"}),(le=function(){return{w:i,m:p}})()}function Qi(n,a,t,e,r,i,o){try{var s=n[i](o),l=s.value}catch(u){return void t(u)}s.done?a(l):Promise.resolve(l).then(e,r)}function Et(n){return function(){var a=this,t=arguments;return new Promise(function(e,r){var i=n.apply(a,t);function o(l){Qi(i,e,r,o,s,"next",l)}function s(l){Qi(i,e,r,o,s,"throw",l)}o(void 0)})}}var $n=new Map,Ji=!1;function ql(n){return new Promise(function(a,t){var e=new FileReader;e.onload=function(){return a(e.result)},e.onerror=t,e.readAsDataURL(n)})}function Yl(n){if(!$n.has(n)){var a=fetch(n).then(function(t){return t.blob()}).then(ql).catch(function(){return $n.delete(n),null});$n.set(n,a)}return $n.get(n)}function Kl(n){return mr.apply(this,arguments)}function mr(){return mr=Et(le().m(function n(a){var t,e,r;return le().w(function(i){for(;;)switch(i.n){case 0:return t=document.createElement("div"),t.innerHTML=a,e=Array.from(t.querySelectorAll("img[src]")),r=e.filter(function(o){return!o.getAttribute("src").startsWith("data:")}),i.n=1,Promise.all(r.map((function(){var o=Et(le().m(function s(l){var u;return le().w(function(d){for(;;)switch(d.n){case 0:return d.n=1,Yl(l.getAttribute("src"));case 1:u=d.v,u&&l.setAttribute("src",u);case 2:return d.a(2)}},s)}));return function(s){return o.apply(this,arguments)}})()));case 1:return i.a(2,t.innerHTML)}},n)})),mr.apply(this,arguments)}function eo(n){return pr.apply(this,arguments)}function pr(){return pr=Et(le().m(function n(a){var t,e,r,i,o,s,l,u,d,c,p,v,f,b=arguments;return le().w(function(g){for(;;)switch(g.n){case 0:if(t=b.length>1&&b[1]!==void 0?b[1]:1,e=a instanceof SVGElement?new XMLSerializer().serializeToString(a):a,r=new DOMParser,i=r.parseFromString(e,"image/svg+xml"),o=i.querySelector("svg"),o){g.n=1;break}return g.a(2,null);case 1:if(s=parseFloat(o.getAttribute("width")||""),l=parseFloat(o.getAttribute("height")||""),(!(s>0)||!(l>0))&&(u=o.getAttribute("viewBox"),u&&(d=u.trim().split(/[\s,]+/),s=parseFloat(d[2]),l=parseFloat(d[3]))),!(!(s>0)||!(l>0))){g.n=2;break}return console.warn("Sigma: SVG label attachment has no parseable dimensions \u2014 skipped."),g.a(2,null);case 2:return c=Math.ceil(s*t),p=Math.ceil(l*t),v=new Blob([e],{type:"image/svg+xml"}),f=URL.createObjectURL(v),g.a(2,new Promise(function(h){var m=new Image;m.onload=function(){var x=document.createElement("canvas");x.width=c,x.height=p,x.getContext("2d").drawImage(m,0,0,c,p),URL.revokeObjectURL(f);try{x.getContext("2d").getImageData(0,0,1,1)}catch(y){if(y instanceof DOMException&&y.name==="SecurityError"){Ji||(Ji=!0,console.warn('Sigma: A label attachment was skipped because the rendered canvas is tainted. SVG with <foreignObject> (used by the "html" attachment type) is blocked in Chromium and Safari. Use type: "canvas" with Canvas 2D rendering instead.')),h(null);return}throw y}h(x)},m.onerror=function(){URL.revokeObjectURL(f),h(null)},m.src=f}))}},n)})),pr.apply(this,arguments)}function Zl(n,a){var t=document.createElement("div");t.style.cssText="position:fixed;left:-99999px;top:0;visibility:hidden;width:max-content;height:max-content",t.innerHTML=(a?"<style>".concat(a,"</style>"):"")+n,document.body.appendChild(t);var e=t.getBoundingClientRect(),r=e.width,i=e.height;return document.body.removeChild(t),{width:Math.ceil(r),height:Math.ceil(i)}}function $l(n,a,t,e){return br.apply(this,arguments)}function br(){return br=Et(le().m(function n(a,t,e,r){var i,o,s,l,u,d,c,p,v=arguments;return le().w(function(f){for(;;)switch(f.n){case 0:return i=v.length>4&&v[4]!==void 0?v[4]:1,o=a instanceof HTMLElement?a.outerHTML:a,f.n=1,Kl(o);case 1:return s=f.v,(e==null||r==null)&&(l=Zl(s,t),e=e??l.width,r=r??l.height),u=Math.ceil(e*i),d=Math.ceil(r*i),c=t?"<style>".concat(t,"</style>"):"",p='<svg xmlns="http://www.w3.org/2000/svg" '+'width="'.concat(u,'" height="').concat(d,'" viewBox="0 0 ').concat(e," ").concat(r,'">')+'<foreignObject width="'.concat(e,'" height="').concat(r,'">')+'<body xmlns="http://www.w3.org/1999/xhtml" style="margin:0;padding:0">'.concat(c).concat(s,"</body>")+"</foreignObject></svg>",f.a(2,eo(p,1))}},n)})),br.apply(this,arguments)}function Ql(n){return xr.apply(this,arguments)}function xr(){return xr=Et(le().m(function n(a){var t,e=arguments,r;return le().w(function(i){for(;;)switch(i.n){case 0:t=e.length>1&&e[1]!==void 0?e[1]:1,r=a.type,i.n=r==="canvas"?1:r==="svg"?2:r==="html"?3:4;break;case 1:return i.a(2,a.canvas);case 2:return i.a(2,eo(a.svg,t));case 3:return i.a(2,$l(a.html,a.css,a.width,a.height,t));case 4:return i.a(2)}},n)})),xr.apply(this,arguments)}var St=2048,Qn=(function(){function n(a,t,e){X(this,n),S(this,"cache",new Map),S(this,"pending",new Set),S(this,"atlas",{}),S(this,"glTexture",null),S(this,"dirty",!0),this.gl=a,this.renderers=t,this.scheduleRender=e,this.packCanvas=document.createElement("canvas"),this.packCanvas.width=St,this.packCanvas.height=St,this.packCtx=this.packCanvas.getContext("2d")}return j(n,[{key:"renderAttachment",value:function(t,e,r){var i=this,o="".concat(t,":").concat(e);if(!(this.cache.has(o)||this.pending.has(o))){var s=this.renderers[e];if(s){var l=s(r);if(l){this.pending.add(o);var u=r.pixelRatio;Promise.resolve(l).then((function(){var d=Et(le().m(function c(p){var v;return le().w(function(f){for(;;)switch(f.n){case 0:if(i.pending.has(o)){f.n=1;break}return f.a(2);case 1:if(i.pending.delete(o),p){f.n=2;break}return f.a(2);case 2:return f.n=3,Ql(p,u);case 3:if(v=f.v,!(!v||v.width===0||v.height===0)){f.n=4;break}return f.a(2);case 4:i.cache.set(o,{image:v,width:v.width,height:v.height}),i.dirty=!0,i.scheduleRender();case 5:return f.a(2)}},c)}));return function(c){return d.apply(this,arguments)}})())}}}}},{key:"regenerateAtlas",value:function(){if(this.dirty){this.dirty=!1;var t=[];if(this.cache.forEach(function(u,d){t.push({key:d,width:u.width,height:u.height,draw:function(p,v,f){p.drawImage(u.image,v,f)}})}),t.length===0){this.atlas={},this.deleteGLTexture();return}var e={x:0,y:0,rowHeight:0,maxRowWidth:0};this.packCtx.clearRect(0,0,St,St);var r=Zn(t,this.packCtx,e),i=r.atlas,o=r.remaining;this.atlas=i,o.length>0&&console.warn("Sigma: ".concat(o.length," label attachment(s) could not fit in the ").concat(St,"x").concat(St," atlas and will not be rendered.")),this.deleteGLTexture();var s=this.gl,l=s.createTexture();s.activeTexture(s.TEXTURE0+Jt),s.bindTexture(s.TEXTURE_2D,l),s.pixelStorei(s.UNPACK_PREMULTIPLY_ALPHA_WEBGL,!0),s.texImage2D(s.TEXTURE_2D,0,s.RGBA,s.RGBA,s.UNSIGNED_BYTE,this.packCanvas),s.pixelStorei(s.UNPACK_PREMULTIPLY_ALPHA_WEBGL,!1),s.texParameteri(s.TEXTURE_2D,s.TEXTURE_MIN_FILTER,s.LINEAR),s.texParameteri(s.TEXTURE_2D,s.TEXTURE_MAG_FILTER,s.LINEAR),s.texParameteri(s.TEXTURE_2D,s.TEXTURE_WRAP_S,s.CLAMP_TO_EDGE),s.texParameteri(s.TEXTURE_2D,s.TEXTURE_WRAP_T,s.CLAMP_TO_EDGE),this.glTexture=l}}},{key:"bindTexture",value:function(t){if(this.glTexture){var e=this.gl;e.activeTexture(e.TEXTURE0+t),e.bindTexture(e.TEXTURE_2D,this.glTexture)}}},{key:"getEntry",value:function(t,e){var r="".concat(t,":").concat(e);return this.atlas[r]||null}},{key:"invalidateNode",value:function(t){var e="".concat(t,":"),r=G(this.cache.keys()),i;try{for(r.s();!(i=r.n()).done;){var o=i.value;o.startsWith(e)&&(this.cache.delete(o),this.dirty=!0)}}catch(d){r.e(d)}finally{r.f()}var s=G(this.pending),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;u.startsWith(e)&&this.pending.delete(u)}}catch(d){s.e(d)}finally{s.f()}}},{key:"restore",value:function(){this.glTexture=null,this.dirty=!0}},{key:"clear",value:function(){this.cache.clear(),this.pending.clear(),this.atlas={},this.dirty=!0,this.deleteGLTexture()}},{key:"kill",value:function(){this.clear(),this.packCanvas=null,this.packCtx=null,this.gl=null}},{key:"deleteGLTexture",value:function(){this.glTexture&&(this.gl.deleteTexture(this.glTexture),this.glTexture=null)}}])})(),tn=(function(){function n(a){X(this,n),S(this,"buckets",new Map),S(this,"keyDepth",new Map);var t=G(a),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;this.buckets.set(r,new Set)}}catch(i){t.e(i)}finally{t.f()}}return j(n,[{key:"has",value:function(t){return this.keyDepth.has(t)}},{key:"getBucket",value:function(t){return this.buckets.get(t)}},{key:"set",value:function(t,e){var r,i=this.keyDepth.get(t);if(i!==e){var o=this.buckets.get(e);if(!o)throw new Error('Sigma: "'.concat(e,'" is not a declared depth layer'));i!==void 0&&((r=this.buckets.get(i))===null||r===void 0||r.delete(t)),o.add(t),this.keyDepth.set(t,e)}}},{key:"remove",value:function(t){var e=this.keyDepth.get(t);e!==void 0&&(this.buckets.get(e).delete(t),this.keyDepth.delete(t))}},{key:"clearAll",value:function(){var t=G(this.buckets.values()),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;r.clear()}}catch(i){t.e(i)}finally{t.f()}this.keyDepth.clear()}},{key:"getSorted",value:function(t,e){var r=this.buckets.get(t);return!r||r.size===0?[]:H(r).sort(function(i,o){return e(i)-e(o)})}}])})(),Jn=(function(n){function a(t,e){return X(this,a),Q(this,a,[t,2,e])}return J(a,n),j(a,[{key:"updateNode",value:function(e,r,i,o,s,l,u,d){var c=this.indexMap.get(e);if(c===void 0)throw new Error('Node "'.concat(e,'" not allocated in NodeDataTexture'));var p=xe(d),v=Z(p,4),f=v[0],b=v[1],g=v[2],h=v[3],m=c*2*4;this.data[m]=r,this.data[m+1]=i,this.data[m+2]=o,this.data[m+3]=s,this.data[m+4]=l,this.data[m+5]=u,this.data[m+6]=f*65536+b*256+g,this.data[m+7]=h/255,this.markDirty(c)}}])})(_t),Jl=1024,eu=1.5,tu=4096,nn=(function(){function n(a,t){var e;if(X(this,n),S(this,"texture",null),S(this,"framebuffer",null),!a.getExtension("EXT_color_buffer_float"))throw new Error("sigma: EXT_color_buffer_float is required for label/edge placement but is unavailable in this WebGL2 context.");this.gl=a,this.channels=t.channels,this.capacity=this.roundUpToPowerOfTwo((e=t.initialCapacity)!==null&&e!==void 0?e:Jl);var r=this.computeDimensions(this.capacity);this.textureWidth=r.width,this.textureHeight=r.height,this.create()}return j(n,[{key:"roundUpToPowerOfTwo",value:function(t){return Math.pow(2,Math.ceil(Math.log2(Math.max(1,t))))}},{key:"computeDimensions",value:function(t){var e=Math.min(t,tu),r=Math.ceil(t/e);return{width:e,height:r}}},{key:"create",value:function(){var t=this.gl,e=this.channels===1?t.R32F:t.RGBA32F,r=this.channels===1?t.RED:t.RGBA;if(this.texture=t.createTexture(),t.activeTexture(t.TEXTURE0),t.bindTexture(t.TEXTURE_2D,this.texture),t.texImage2D(t.TEXTURE_2D,0,e,this.textureWidth,this.textureHeight,0,r,t.FLOAT,null),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MIN_FILTER,t.NEAREST),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_MAG_FILTER,t.NEAREST),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_S,t.CLAMP_TO_EDGE),t.texParameteri(t.TEXTURE_2D,t.TEXTURE_WRAP_T,t.CLAMP_TO_EDGE),this.framebuffer=t.createFramebuffer(),t.bindFramebuffer(t.FRAMEBUFFER,this.framebuffer),t.framebufferTexture2D(t.FRAMEBUFFER,t.COLOR_ATTACHMENT0,t.TEXTURE_2D,this.texture,0),t.checkFramebufferStatus(t.FRAMEBUFFER)!==t.FRAMEBUFFER_COMPLETE)throw new Error("sigma: float framebuffer for frame-pass placement is incomplete.");t.bindFramebuffer(t.FRAMEBUFFER,null),t.bindTexture(t.TEXTURE_2D,null)}},{key:"ensureCapacity",value:function(t){if(!(t<=this.capacity)){var e=this.gl;this.capacity=this.roundUpToPowerOfTwo(Math.ceil(t*eu));var r=this.computeDimensions(this.capacity);this.textureWidth=r.width,this.textureHeight=r.height,this.texture&&e.deleteTexture(this.texture),this.framebuffer&&e.deleteFramebuffer(this.framebuffer),this.create()}}},{key:"bindAsRenderTarget",value:function(){var t=this.gl;t.bindFramebuffer(t.FRAMEBUFFER,this.framebuffer),t.viewport(0,0,this.textureWidth,this.textureHeight)}},{key:"bind",value:function(t){var e=this.gl;e.activeTexture(e.TEXTURE0+t),e.bindTexture(e.TEXTURE_2D,this.texture)}},{key:"getTexture",value:function(){return this.texture}},{key:"getTextureWidth",value:function(){return this.textureWidth}},{key:"getTextureHeight",value:function(){return this.textureHeight}},{key:"restore",value:function(){this.gl.getExtension("EXT_color_buffer_float"),this.create()}},{key:"kill",value:function(){var t=this.gl;this.texture&&(t.deleteTexture(this.texture),this.texture=null),this.framebuffer&&(t.deleteFramebuffer(this.framebuffer),this.framebuffer=null)}}])})(),ea=(function(n){function a(t,e){return X(this,a),Q(this,a,[t,2,e])}return J(a,n),j(a,[{key:"updateEdge",value:function(e,r,i,o,s,l){var u=arguments.length>6&&arguments[6]!==void 0?arguments[6]:0,d=arguments.length>7&&arguments[7]!==void 0?arguments[7]:0,c=arguments.length>8&&arguments[8]!==void 0?arguments[8]:0,p=this.indexMap.get(e);if(p===void 0)throw new Error('Edge "'.concat(e,'" not allocated in EdgeDataTexture'));var v=p*this.TEXELS_PER_ITEM*4;this.data[v+0]=r,this.data[v+1]=i,this.data[v+2]=o,this.data[v+3]=0,this.data[v+4]=s,this.data[v+5]=l,this.data[v+6]=u,this.data[v+7]=(d&15)<<4|c&15,this.markDirty(p)}}])})(_t);var wc=Se(Ze()),Ic=Se(An());function nu(n,a){if(n==null)return{};var t={};for(var e in n)if({}.hasOwnProperty.call(n,e)){if(a.indexOf(e)!==-1)continue;t[e]=n[e]}return t}function to(n,a){if(n==null)return{};var t,e,r=nu(n,a);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(n);for(e=0;e<i.length;e++)t=i[e],a.indexOf(t)===-1&&{}.propertyIsEnumerable.call(n,t)&&(r[t]=n[t])}return r}var au=["factor"],ru=["factor"],no=1.5,na={x:.5,y:.5,angle:0,ratio:1},Sr=(function(n){function a(){var t;X(this,a);for(var e=arguments.length,r=new Array(e),i=0;i<e;i++)r[i]=arguments[i];return t=Q(this,a,[].concat(r)),S(t,"minRatio",null),S(t,"maxRatio",null),S(t,"enabled",!0),S(t,"enabledZooming",!0),S(t,"enabledPanning",!0),S(t,"enabledRotation",!0),S(t,"constrainState",null),S(t,"state",O({},na)),S(t,"previousState",O({},na)),S(t,"nextFrame",null),S(t,"currentAnimationFrom",null),S(t,"currentAnimationTo",null),S(t,"animationCallback",null),t}return J(a,n),j(a,[{key:"x",get:function(){return this.state.x}},{key:"y",get:function(){return this.state.y}},{key:"angle",get:function(){return this.state.angle}},{key:"ratio",get:function(){return this.state.ratio}},{key:"getState",value:function(){return O({},this.state)}},{key:"getPreviousState",value:function(){return O({},this.previousState)}},{key:"getBoundedRatio",value:function(e){var r=e;return typeof this.minRatio=="number"&&(r=Math.max(r,this.minRatio)),typeof this.maxRatio=="number"&&(r=Math.min(r,this.maxRatio)),r}},{key:"validateState",value:function(e){var r=this.getState();return this.enabledPanning&&typeof e.x=="number"&&(r.x=e.x),this.enabledPanning&&typeof e.y=="number"&&(r.y=e.y),this.enabledZooming&&typeof e.ratio=="number"&&(r.ratio=this.getBoundedRatio(e.ratio)),this.enabledRotation&&typeof e.angle=="number"&&(r.angle=e.angle),this.constrainState?this.constrainState(r):r}},{key:"isAnimating",value:function(){return this.nextFrame!==null}},{key:"setState",value:function(e){if(!this.enabled)return this;var r=this.validateState(e);return Rn(this.state,r)?this:(this.previousState=this.state,this.state=r,this.emit("updated",this.getState()),this)}},{key:"updateState",value:function(e){return this.setState(e(this.getState())),this}},{key:"animate",value:function(e,r){var i=this;return this.enabled?new Promise(function(o){return i.runAnimation(e,O(O({},Gt),r),o)}):Promise.resolve()}},{key:"cancelAnimation",value:function(){return this.nextFrame!==null&&(cancelAnimationFrame(this.nextFrame),this.nextFrame=null),this.resolveAnimation(),this.emitAnimationEnd(!1),this}},{key:"zoomIn",value:function(){var e=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{},r=e.factor,i=r===void 0?no:r,o=to(e,au);return this.animate({ratio:this.ratio/i},o)}},{key:"zoomOut",value:function(){var e=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{},r=e.factor,i=r===void 0?no:r,o=to(e,ru);return this.animate({ratio:this.ratio*i},o)}},{key:"reset",value:function(e){return this.animate(na,e)}},{key:"runAnimation",value:function(e,r,i){var o=this,s=ke(r.easing),l=Date.now(),u=this.getState(),d=this.validateState(e),c=function(){if(!o.enabled){o.cancelAnimation();return}var v=r.duration>0?(Date.now()-l)/r.duration:1;if(v>=1){o.nextFrame=null,o.setState(d),o.resolveAnimation(),o.emitAnimationEnd(!0);return}var f=s(v);o.setState({x:u.x+(d.x-u.x)*f,y:u.y+(d.y-u.y)*f,angle:u.angle+(d.angle-u.angle)*f,ratio:u.ratio+(d.ratio-u.ratio)*f}),o.nextFrame=requestAnimationFrame(c)};this.cancelAnimation(),this.currentAnimationFrom=u,this.currentAnimationTo=d,this.animationCallback=i,this.emit("animationStart",{from:u,to:d}),c()}},{key:"resolveAnimation",value:function(){var e=this.animationCallback;this.animationCallback=null,e&&e()}},{key:"emitAnimationEnd",value:function(e){var r=this.currentAnimationFrom,i=this.currentAnimationTo;!r||!i||(this.currentAnimationFrom=null,this.currentAnimationTo=null,this.emit("animationEnd",{from:r,to:i,completed:e}))}}],[{key:"from",value:function(e){var r=new a;return r.setState(e)}}])})(Sn);function ue(n,a){var t=a.getBoundingClientRect();return{x:n.clientX-t.left,y:n.clientY-t.top}}function Te(n,a){var t=O(O({},ue(n,a)),{},{sigmaDefaultPrevented:!1,preventSigmaDefault:function(){t.sigmaDefaultPrevented=!0},original:n});return t}function et(n){var a="x"in n?n:O(O({},n.touches[0]||n.previousTouches[0]),{},{original:n.original,sigmaDefaultPrevented:n.sigmaDefaultPrevented,preventSigmaDefault:function(){n.sigmaDefaultPrevented=!0,a.sigmaDefaultPrevented=!0}});return a}function iu(n,a){var t=Te(n,a);return t.delta=po(n),t}var ou=2;function aa(n){for(var a=[],t=0,e=Math.min(n.length,ou);t<e;t++)a.push(n[t]);return a}function an(n,a,t){var e={touches:aa(n.touches).map(function(r){return ue(r,t)}),previousTouches:a.map(function(r){return ue(r,t)}),sigmaDefaultPrevented:!1,preventSigmaDefault:function(){e.sigmaDefaultPrevented=!0},original:n};return e}function po(n){if(typeof n.deltaY<"u")return n.deltaY*-3/360;if(typeof n.detail<"u")return n.detail/-9;throw new Error("Captor: could not extract delta from event.")}var bo=(function(n){function a(t,e){var r;return X(this,a),r=Q(this,a),r.container=t,r.renderer=e,r}return J(a,n),j(a)})(Sn),su=["doubleClickTimeout","doubleClickZoomingDuration","doubleClickZoomingRatio","dragTimeout","draggedEventsTolerance","enableCameraMouseRotation","gestureTarget","inertiaDuration","inertiaRatio","zoomDuration","zoomingRatio"],lu=su.reduce(function(n,a){return O(O({},n),{},S({},a,Cn[a]))},{});function rn(n){return n instanceof PointerEvent&&n.pointerType==="touch"}var xo=(function(n){function a(t,e){var r;return X(this,a),r=Q(this,a,[t,e]),S(r,"enabled",!0),S(r,"draggedEvents",0),S(r,"downStartTime",null),S(r,"lastMouseX",null),S(r,"lastMouseY",null),S(r,"isMouseDown",!1),S(r,"isMoving",!1),S(r,"isPanningStage",!1),S(r,"movingTimeout",null),S(r,"startCameraState",null),S(r,"clicks",0),S(r,"doubleClickTimeout",null),S(r,"isRightMouseDown",!1),S(r,"startRotationAngle",null),S(r,"startCameraAngle",null),S(r,"currentWheelDirection",0),S(r,"lastWheelAnimationId",0),S(r,"settings",lu),r.handleRightClick=r.handleRightClick.bind(r),r.handleDown=r.handleDown.bind(r),r.handleUp=r.handleUp.bind(r),r.handleMove=r.handleMove.bind(r),r.handleWheel=r.handleWheel.bind(r),r.handleLeave=r.handleLeave.bind(r),r.handleEnter=r.handleEnter.bind(r),t.addEventListener("contextmenu",r.handleRightClick,{capture:!1}),t.addEventListener("pointerdown",r.handleDown,{capture:!1}),t.addEventListener("wheel",r.handleWheel,{capture:!1,passive:!1}),t.addEventListener("pointerleave",r.handleLeave,{capture:!1}),t.addEventListener("pointerenter",r.handleEnter,{capture:!1}),document.addEventListener("pointermove",r.handleMove,{capture:!1}),document.addEventListener("pointerup",r.handleUp,{capture:!1}),r}return J(a,n),j(a,[{key:"kill",value:function(){var e=this.container;e.removeEventListener("contextmenu",this.handleRightClick),e.removeEventListener("pointerdown",this.handleDown),e.removeEventListener("wheel",this.handleWheel),e.removeEventListener("pointerleave",this.handleLeave),e.removeEventListener("pointerenter",this.handleEnter),document.removeEventListener("pointermove",this.handleMove),document.removeEventListener("pointerup",this.handleUp)}},{key:"handleClick",value:function(e){var r=this;if(this.enabled){if(this.clicks++,this.clicks===2)return this.clicks=0,typeof this.doubleClickTimeout=="number"&&(clearTimeout(this.doubleClickTimeout),this.doubleClickTimeout=null),this.handleDoubleClick(e);setTimeout(function(){r.clicks=0,r.doubleClickTimeout=null},this.settings.doubleClickTimeout),this.draggedEvents<this.settings.draggedEventsTolerance&&this.emit("click",Te(e,this.container))}}},{key:"handleRightClick",value:function(e){this.enabled&&(this.settings.enableCameraMouseRotation&&e.preventDefault(),this.emit("rightClick",Te(e,this.container)))}},{key:"handleDoubleClick",value:function(e){if(this.enabled){e.preventDefault(),e.stopPropagation();var r=Te(e,this.container);if(this.emit("doubleClick",r),!r.sigmaDefaultPrevented){var i=this.renderer.getCamera(),o=i.getBoundedRatio(i.getState().ratio/this.settings.doubleClickZoomingRatio);i.animate(this.renderer.getViewportZoomedState(ue(e,this.container),o),{easing:"quadraticInOut",duration:this.settings.doubleClickZoomingDuration})}}}},{key:"handleDown",value:function(e){if(!(!this.enabled||rn(e))){if(e.button===0){this.startCameraState=this.renderer.getCamera().getState();var r=ue(e,this.container),i=r.x,o=r.y;this.lastMouseX=i,this.lastMouseY=o,this.draggedEvents=0,this.downStartTime=Date.now(),this.isMouseDown=!0}if(e.button===2&&this.settings.enableCameraMouseRotation){var s=ue(e,this.container),l=s.x,u=s.y,d=this.container.offsetWidth/2,c=this.container.offsetHeight/2;this.startRotationAngle=Math.atan2(u-c,l-d),this.startCameraAngle=this.renderer.getCamera().getState().angle,this.isRightMouseDown=!0}this.emit("mousedown",Te(e,this.container))}}},{key:"handleUp",value:function(e){var r=this;if(!(!this.enabled||rn(e)||!this.isMouseDown&&!this.isRightMouseDown)){if(this.isRightMouseDown){this.isRightMouseDown=!1,this.startRotationAngle=null,this.startCameraAngle=null,this.emit("mouseup",Te(e,this.container));return}var i=this.renderer.getCamera();this.isMouseDown=!1,this.isPanningStage&&(this.isPanningStage=!1,this.renderer._setPanning(!1)),typeof this.movingTimeout=="number"&&(clearTimeout(this.movingTimeout),this.movingTimeout=null);var o=ue(e,this.container),s=o.x,l=o.y,u=i.getState(),d=i.getPreviousState();this.isMoving?i.animate({x:u.x+this.settings.inertiaRatio*(u.x-d.x),y:u.y+this.settings.inertiaRatio*(u.y-d.y)},{duration:this.settings.inertiaDuration,easing:"quadraticOut"}):(this.lastMouseX!==s||this.lastMouseY!==l)&&i.setState({x:u.x,y:u.y}),this.isMoving=!1,setTimeout(function(){var c=r.draggedEvents>0;r.draggedEvents=0;var p=r.renderer.getSetting("hideEdgesOnMove")||r.renderer.getSetting("hideLabelsOnMove");c&&p&&r.renderer.refresh()},0),this.emit("mouseup",Te(e,this.container)),(e.target===this.container||e.composedPath()[0]===this.container)&&this.handleClick(e)}}},{key:"handleMove",value:function(e){var r=this;if(!(!this.enabled||rn(e))){var i=Te(e,this.container);if(this.emit("mousemovebody",i),(e.target===this.container||e.composedPath()[0]===this.container)&&this.emit("mousemove",i),this.isMouseDown&&this.draggedEvents++,!i.sigmaDefaultPrevented){if(this.isMouseDown){this.isMoving=!0,typeof this.movingTimeout=="number"&&clearTimeout(this.movingTimeout),this.movingTimeout=window.setTimeout(function(){r.movingTimeout=null,r.isMoving=!1},this.settings.dragTimeout);var o=this.renderer.getCamera(),s=ue(e,this.container),l=s.x,u=s.y,d=this.renderer.viewportToFramedGraph({x:this.lastMouseX,y:this.lastMouseY}),c=this.renderer.viewportToFramedGraph({x:l,y:u}),p=d.x-c.x,v=d.y-c.y,f=o.getState(),b=f.x+p,g=f.y+v;this.isPanningStage||(this.isPanningStage=!0,this.renderer._setPanning(!0)),o.setState({x:b,y:g}),this.lastMouseX=l,this.lastMouseY=u,e.preventDefault(),e.stopPropagation()}if(this.isRightMouseDown){var h=ue(e,this.container),m=h.x,x=h.y,y=this.container.offsetWidth/2,_=this.container.offsetHeight/2,T=Math.atan2(x-_,m-y),R=T-this.startRotationAngle,E=this.renderer.getCamera();E.setState({angle:this.startCameraAngle+R}),e.preventDefault(),e.stopPropagation()}}}}},{key:"handleLeave",value:function(e){rn(e)||this.emit("mouseleave",Te(e,this.container))}},{key:"handleEnter",value:function(e){rn(e)||this.emit("mouseenter",Te(e,this.container))}},{key:"handleWheel",value:function(e){var r=this,i=this.renderer.getCamera();if(!(!this.enabled||!i.enabledZooming)){var o=iu(e,this.container);if(this.emit("wheel",o),!o.sigmaDefaultPrevented){var s=this.settings.gestureTarget;if(s!=="page"){if(s==="shared"&&!e.ctrlKey&&!e.metaKey){this.renderer._showGestureHint("wheel");return}var l=po(e);if(l){e.preventDefault(),e.stopPropagation();var u=i.getState().ratio,d=l>0?1/this.settings.zoomingRatio:this.settings.zoomingRatio,c=i.getBoundedRatio(u*d),p=l>0?1:-1,v=Date.now();if(u!==c&&!(this.currentWheelDirection===p&&this.lastWheelTriggerTime&&v-this.lastWheelTriggerTime<this.settings.zoomDuration/5)){var f=++this.lastWheelAnimationId;i.animate(this.renderer.getViewportZoomedState(ue(e,this.container),c),{easing:"quadraticOut",duration:this.settings.zoomDuration}).then(function(){r.lastWheelAnimationId===f&&(r.currentWheelDirection=0)}),this.currentWheelDirection=p,this.lastWheelTriggerTime=v}}}}}}},{key:"setSettings",value:function(e){this.settings=e}}])})(bo),uu=["dragTimeout","gestureTarget","inertiaDuration","inertiaRatio","doubleClickTimeout","doubleClickZoomingRatio","doubleClickZoomingDuration","tapMoveTolerance"],du=uu.reduce(function(n,a){return O(O({},n),{},S({},a,Cn[a]))},{}),yo=(function(n){function a(t,e){var r;return X(this,a),r=Q(this,a,[t,e]),S(r,"enabled",!0),S(r,"isMoving",!1),S(r,"hasMoved",!1),S(r,"isPanningStage",!1),S(r,"isZoomingStage",!1),S(r,"touchMode",0),S(r,"startTouchesPositions",[]),S(r,"lastTouches",[]),S(r,"lastTap",null),S(r,"settings",du),r.handleStart=r.handleStart.bind(r),r.handleLeave=r.handleLeave.bind(r),r.handleMove=r.handleMove.bind(r),t.addEventListener("touchstart",r.handleStart,{capture:!1}),t.addEventListener("touchcancel",r.handleLeave,{capture:!1}),document.addEventListener("touchend",r.handleLeave,{capture:!1,passive:!1}),document.addEventListener("touchmove",r.handleMove,{capture:!1,passive:!1}),r}return J(a,n),j(a,[{key:"kill",value:function(){var e=this.container;e.removeEventListener("touchstart",this.handleStart),e.removeEventListener("touchcancel",this.handleLeave),document.removeEventListener("touchend",this.handleLeave),document.removeEventListener("touchmove",this.handleMove)}},{key:"getDimensions",value:function(){return{width:this.container.offsetWidth,height:this.container.offsetHeight}}},{key:"doesCapture",value:function(e){var r=this.settings.gestureTarget;return r==="graph"?!0:r==="page"?!1:e>=2}},{key:"syncStageFlags",value:function(){var e=this.touchMode===1&&this.hasMoved,r=this.touchMode===2;e!==this.isPanningStage&&(this.isPanningStage=e,this.renderer._setPanning(e)),r!==this.isZoomingStage&&(this.isZoomingStage=r,this.renderer._setZooming(r))}},{key:"handleStart",value:function(e){var r=this;if(this.enabled){var i=aa(e.touches);if(this.touchMode=i.length,this.startCameraState=this.renderer.getCamera().getState(),this.startTouchesPositions=i.map(function(v){return ue(v,r.container)}),this.touchMode===2){var o=Z(this.startTouchesPositions,2),s=o[0],l=s.x,u=s.y,d=o[1],c=d.x,p=d.y;this.startTouchesAngle=Math.atan2(p-u,c-l),this.startTouchesDistance=Math.sqrt(Math.pow(c-l,2)+Math.pow(p-u,2))}this.syncStageFlags(),this.emit("touchdown",an(e,this.lastTouches,this.container)),this.lastTouches=i,this.lastTouchesPositions=this.startTouchesPositions,e.cancelable&&(this.doesCapture(e.touches.length)||this.renderer._hasNodeDrag())&&e.preventDefault()}}},{key:"handleLeave",value:function(e){if(!(!this.enabled||!this.startTouchesPositions.length)){switch(e.cancelable&&this.doesCapture(this.touchMode)&&e.preventDefault(),this.movingTimeout&&(this.isMoving=!1,clearTimeout(this.movingTimeout)),this.touchMode){case 2:if(e.touches.length===1){this.handleStart(e);break}case 1:if(this.isMoving){var r=this.renderer.getCamera(),i=r.getState(),o=r.getPreviousState();r.animate({x:i.x+this.settings.inertiaRatio*(i.x-o.x),y:i.y+this.settings.inertiaRatio*(i.y-o.y)},{duration:this.settings.inertiaDuration,easing:"quadraticOut"})}this.hasMoved=!1,this.isMoving=!1,this.touchMode=0;break}if(this.syncStageFlags(),this.emit("touchup",an(e,this.lastTouches,this.container)),!e.touches.length){var s=ue(this.lastTouches[0],this.container),l=this.startTouchesPositions[0],u=Math.pow(s.x-l.x,2)+Math.pow(s.y-l.y,2);if(!e.touches.length&&u<Math.pow(this.settings.tapMoveTolerance,2))if(this.lastTap&&Date.now()-this.lastTap.time<this.settings.doubleClickTimeout){var d=an(e,this.lastTouches,this.container);if(this.emit("doubletap",d),this.lastTap=null,!d.sigmaDefaultPrevented&&this.settings.gestureTarget!=="page"){var c=this.renderer.getCamera(),p=c.getBoundedRatio(c.getState().ratio/this.settings.doubleClickZoomingRatio);c.animate(this.renderer.getViewportZoomedState(s,p),{easing:"quadraticInOut",duration:this.settings.doubleClickZoomingDuration})}}else{var v=an(e,this.lastTouches,this.container);this.emit("tap",v),this.lastTap={time:Date.now(),position:v.touches[0]||v.previousTouches[0]}}}this.lastTouches=aa(e.touches),this.startTouchesPositions=[]}}},{key:"handleMove",value:function(e){var r=this;if(!(!this.enabled||!this.startTouchesPositions.length)){var i=this.doesCapture(e.touches.length);i&&e.preventDefault();var o=aa(e.touches),s=o.map(function(B){return ue(B,r.container)}),l=this.lastTouches;this.lastTouches=o,this.lastTouchesPositions=s;var u=an(e,l,this.container);if(this.emit("touchmove",u),!u.sigmaDefaultPrevented&&(this.hasMoved||(this.hasMoved=s.some(function(B,U){var V=r.startTouchesPositions[U];return V&&(B.x!==V.x||B.y!==V.y)})),!!this.hasMoved)){if(!i){this.settings.gestureTarget==="shared"&&this.renderer._showGestureHint("touch");return}this.isMoving=!0,this.syncStageFlags(),this.movingTimeout&&clearTimeout(this.movingTimeout),this.movingTimeout=window.setTimeout(function(){r.isMoving=!1},this.settings.dragTimeout);var d=this.renderer.getCamera(),c=this.startCameraState,p=this.renderer.getSetting("stagePadding");switch(this.touchMode){case 1:{var v=this.renderer.viewportToFramedGraph((this.startTouchesPositions||[])[0]),f=v.x,b=v.y,g=this.renderer.viewportToFramedGraph(s[0]),h=g.x,m=g.y;d.setState({x:c.x+f-h,y:c.y+b-m});break}case 2:{var x={x:.5,y:.5,angle:0,ratio:1},y=s[0],_=y.x,T=y.y,R=s[1],E=R.x,D=R.y,P=Math.atan2(D-T,E-_)-this.startTouchesAngle,w=Math.hypot(D-T,E-_)/this.startTouchesDistance,A=d.getBoundedRatio(c.ratio/w);x.ratio=A,x.angle=c.angle+P;var F=this.getDimensions(),L=this.renderer.viewportToFramedGraph((this.startTouchesPositions||[])[0],{cameraState:c}),k=Math.min(F.width,F.height)-2*p,N=k/F.width,z=k/F.height,I=A/k,C=_-k/2/N,M=T-k/2/z,W=Pt({x:C,y:M},x.angle);C=W.x,M=W.y,x.x=L.x-C*I,x.y=L.y+M*I,d.setState(x);break}}}}}},{key:"setSettings",value:function(e){this.settings=e}}])})(bo),cu=(function(){function n(a,t,e,r){X(this,n),S(this,"pendingNode",null),S(this,"session",null),this.graph=a,this.viewportToGraph=t,this.setNodesState=e,this.emit=r}return j(n,[{key:"start",value:function(t,e,r,i,o){var s=r(t),l=!1;if(this.emit("nodeDragStart",{node:t,allDraggedNodes:s,event:e,preventSigmaDefault:function(){l=!0}}),l)return!1;var u=new Map,d=G(s),c;try{for(d.s();!(c=d.n()).done;){var p=c.value;u.set(p,{x:this.graph.getNodeAttribute(p,i),y:this.graph.getNodeAttribute(p,o)})}}catch(v){d.e(v)}finally{d.f()}return this.session={node:t,allNodes:s,startPosition:this.viewportToGraph(e),startNodePositions:u,xAttr:i,yAttr:o},this.setNodesState(s,{isDragged:!0}),!0}},{key:"applyMove",value:function(t,e){var r=this.session,i=r.allNodes,o=r.startNodePositions,s=r.startPosition,l=r.xAttr,u=r.yAttr,d=this.viewportToGraph(t),c={x:d.x-s.x,y:d.y-s.y},p=G(i),v;try{for(p.s();!(v=p.n()).done;){var f=v.value,b=o.get(f);if(!(!b||!this.graph.hasNode(f))){var g={x:b.x+c.x,y:b.y+c.y};e?this.graph.mergeNodeAttributes(f,e(g,f)):(this.graph.setNodeAttribute(f,l,g.x),this.graph.setNodeAttribute(f,u,g.y))}}}catch(h){p.e(h)}finally{p.f()}}},{key:"end",value:function(){if(this.pendingNode=null,!this.session)return null;var t=this.session,e=t.node,r=t.allNodes;return this.setNodesState(r,{isDragged:!1}),this.session=null,{node:e,allNodes:r}}},{key:"removeNode",value:function(t){t===this.pendingNode&&(this.pendingNode=null),this.session&&(this.session.node===t?(this.setNodesState(this.session.allNodes,{isDragged:!1}),this.session=null):this.session.allNodes.includes(t)&&(this.session.allNodes=this.session.allNodes.filter(function(e){return e!==t}),this.session.startNodePositions.delete(t)))}},{key:"clear",value:function(){this.pendingNode=null,this.session=null}}])})(),hu=(function(){function n(a,t){X(this,n),S(this,"groups",new Map),S(this,"edgeToGroupKey",new Map),this.graph=a,this.onGroupChanged=t}return j(n,[{key:"getGroupKey",value:function(t){var e=this.graph.source(t),r=this.graph.target(t);return e<r?"".concat(e,"\0").concat(r):"".concat(r,"\0").concat(e)}},{key:"sortGroup",value:function(t,e){var r=this,i=e.split("\0")[0];t.sort(function(o,s){var l=r.graph.source(o)===i||!r.graph.isDirected(o)?0:1,u=r.graph.source(s)===i||!r.graph.isDirected(s)?0:1;return l-u})}},{key:"register",value:function(t){var e=this.getGroupKey(t),r=this.groups.get(e);r||(r=[],this.groups.set(e,r)),r.includes(t)||r.push(t),this.edgeToGroupKey.set(t,e),this.sortGroup(r,e),this.onGroupChanged(r,r.length)}},{key:"unregister",value:function(t){var e=this.edgeToGroupKey.get(t);if(e){this.edgeToGroupKey.delete(t);var r=this.groups.get(e);if(r){var i=r.indexOf(t);i!==-1&&r.splice(i,1),r.length===0?this.groups.delete(e):this.onGroupChanged(r,r.length)}}}},{key:"getGroup",value:function(t){var e,r=this.edgeToGroupKey.get(t);return r?(e=this.groups.get(r))!==null&&e!==void 0?e:[]:[]}},{key:"getSiblings",value:function(t){return this.getGroup(t).filter(function(e){return e!==t})}},{key:"rebuild",value:function(){var t=this;this.groups.clear(),this.edgeToGroupKey.clear(),this.graph.forEachEdge(function(l){var u=t.getGroupKey(l),d=t.groups.get(u);d||(d=[],t.groups.set(u,d)),d.push(l),t.edgeToGroupKey.set(l,u)});var e=G(this.groups),r;try{for(e.s();!(r=e.n()).done;){var i=Z(r.value,2),o=i[0],s=i[1];this.sortGroup(s,o),this.onGroupChanged(s,s.length)}}catch(l){e.e(l)}finally{e.f()}}},{key:"clear",value:function(){this.groups.clear(),this.edgeToGroupKey.clear()}}])})();function ao(n,a){var t;if(n===!1||n==="extend"||n==="separate")return n;var e=n[a];return e!==void 0?e:(t=n.default)!==null&&t!==void 0?t:!1}function ro(n){return n===!1?!1:n==="extend"||n==="separate"?!0:Object.values(n).some(function(a){return a==="extend"||a==="separate"})}function io(n){return n==="separate"?!0:n===!1||n==="extend"?!1:n.default==="separate"?!0:Object.values(n).includes("separate")}var ne={node:{parent:null,eventSuffix:"Node",payloadKey:"node",isEnabled:function(){return!0},writesPickingThisFrame:function(){return!0},setHover:function(a,t,e){return a.setNodeState(t,{isHovered:e})},getCursor:function(a,t){var e;return(e=a.nodeDataCache[t])===null||e===void 0?void 0:e.cursor},isHitValid:function(a,t){var e;return((e=a.nodeDataCache[t])===null||e===void 0?void 0:e.visibility)!=="hidden"}},edge:{parent:null,eventSuffix:"Edge",payloadKey:"edge",isEnabled:function(a){return!!a.settings.enableEdgeEvents},writesPickingThisFrame:function(a){return!!a.settings.enableEdgeEvents},setHover:function(a,t,e){return a.setEdgeState(t,{isHovered:e})},getCursor:function(a,t){var e;return(e=a.edgeDataCache[t])===null||e===void 0?void 0:e.cursor}},nodeLabel:{parent:"node",eventSuffix:"NodeLabel",payloadKey:"node",isEnabled:function(a){return io(a.settings.nodeLabelEvents)},writesPickingThisFrame:function(a){return ro(a.settings.nodeLabelEvents)},setHover:function(a,t,e){return a.setNodeState(t,{isLabelHovered:e})},getCursor:function(a,t){var e;return(e=a.nodeDataCache[t])===null||e===void 0?void 0:e.labelCursor},resolveForVerb:function(a,t,e){var r=ao(e.settings.nodeLabelEvents,t);return r===!1?null:r==="extend"?{kind:"node",key:a.key}:a}},edgeLabel:{parent:"edge",eventSuffix:"EdgeLabel",payloadKey:"edge",isEnabled:function(a){return io(a.settings.edgeLabelEvents)},writesPickingThisFrame:function(a){return ro(a.settings.edgeLabelEvents)},setHover:function(a,t,e){return a.setEdgeState(t,{isLabelHovered:e})},getCursor:function(a,t){var e;return(e=a.edgeDataCache[t])===null||e===void 0?void 0:e.labelCursor},resolveForVerb:function(a,t,e){var r=ao(e.settings.edgeLabelEvents,t);return r===!1?null:r==="extend"?{kind:"edge",key:a.key}:a}}},at=["node","edge","nodeLabel","edgeLabel"];function fu(){return{lookup:[null],idsByKind:{node:new Map,edge:new Map,nodeLabel:new Map,edgeLabel:new Map},nextId:1}}function nt(n,a,t){var e;return(e=n.idsByKind[a].get(t))!==null&&e!==void 0?e:0}function yr(n,a){var t=G(at),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;if(r===a||ne[r].parent===a){var i=G(n.idsByKind[r].values()),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;n.lookup[s]=null}}catch(p){i.e(p)}finally{i.f()}n.idsByKind[r]=new Map}}}catch(p){t.e(p)}finally{t.f()}var l=1,u=G(at),d;try{for(u.s();!(d=u.n()).done;){var c=d.value;if(c===a)break;l+=n.idsByKind[c].size}}catch(p){u.e(p)}finally{u.f()}n.nextId=l}function oo(n,a,t){var e=n.nextId++;return n.idsByKind[a].set(t,e),n.lookup[e]={kind:a,key:t},e}function gu(n,a){var t=G(at),e;try{for(t.s();!(e=t.n()).done;){var r=e.value;if(ne[r].parent!==null){var i=G(n.idsByKind[r].values()),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;n.lookup[s]=null}}catch(_){i.e(_)}finally{i.f()}n.idsByKind[r]=new Map}}}catch(_){t.e(_)}finally{t.f()}n.nextId=1;var l=G(at),u;try{for(l.s();!(u=l.n()).done;){var d=u.value;if(ne[d].parent===null){var c=G(n.idsByKind[d].values()),p;try{for(c.s();!(p=c.n()).done;){var v=p.value;v>=n.nextId&&(n.nextId=v+1)}}catch(_){c.e(_)}finally{c.f()}}}}catch(_){l.e(_)}finally{l.f()}var f=G(at),b;try{for(f.s();!(b=f.n()).done;){var g=b.value,h=ne[g];if(!(h.parent===null||!h.isEnabled(a))){var m=G(n.idsByKind[h.parent].keys()),x;try{for(m.s();!(x=m.n()).done;){var y=x.value;n.idsByKind[g].set(y,n.nextId),n.lookup[n.nextId]={kind:g,key:y},n.nextId++}}catch(_){m.e(_)}finally{m.f()}}}}catch(_){f.e(_)}finally{f.f()}}function vu(n,a){var t=G(at),e;try{for(t.s();!(e=t.n()).done;){var r=e.value,i=n[r],o=a[r];if(i!==o){if(i.size!==o.size)return!1;var s=G(i),l;try{for(s.s();!(l=s.n()).done;){var u=Z(l.value,2),d=u[0],c=u[1];if(o.get(d)!==c)return!1}}catch(p){s.e(p)}finally{s.f()}}}}catch(p){t.e(p)}finally{t.f()}return!0}function so(n,a,t){ne[a.kind].setHover(n,a.key,t)}function mu(n,a){return ne[a.kind].getCursor(n,a.key)}function on(n,a){return"".concat(a).concat(ne[n].eventSuffix)}function sn(n,a){return O(O({},a),{},S({},ne[n.kind].payloadKey,n.key))}function pu(n,a,t){var e=ne[a.kind].resolveForVerb;return e?e(a,t,n):a}function bu(n,a){var t=ne[a.kind].isHitValid;return t?t(n,a.key):!0}function _r(n){return at.filter(function(a){return a===n||ne[a].parent===n})}function _o(n,a,t){return a&&(a=pu(n,a,t)),a&&!bu(n,a)&&(a=null),a}function Tr(n,a,t){var e=t==="wheel"?n.stateManager.hovered:n.getHitAtPosition(a);return _o(n,e,t)}function xu(n,a){return!n||!a?n===a:n.kind===a.kind&&n.key===a.key}function To(n,a,t){var e={event:t,preventSigmaDefault:function(){return t.preventSigmaDefault()}},r=n.dragManager.session,i=r?{kind:"node",key:r.node}:_o(n,a,"enter"),o=n.stateManager,s=o.hovered;xu(s,i)||(s&&(so(n,s,!1),n.emit(on(s.kind,"leave"),sn(s,e))),o.setHovered(i),i&&(so(n,i,!0),n.emit(on(i.kind,"enter"),sn(i,e))),n.updateContainerCursor())}function yu(n,a,t,e){e.handleResize=function(){return n.scheduleRefresh()},window.addEventListener("resize",e.handleResize),e.handleMove=function(i){n.hoverResolver.pointerMoved(et(i))},e.handleMoveBody=function(i){var o=et(i),s=n.dragManager;if(s.pendingNode&&!s.session){var l=n.nodeStyleAnalysis,u=l.xAttribute,d=l.yAttribute,c=n.settings;s.start(s.pendingNode,o,c.getDraggedNodes,u||"x",d||"y"),s.pendingNode=null}s.session&&(s.applyMove(o,n.settings.dragPositionToAttributes),n.emit("nodeDrag",{node:s.session.node,allDraggedNodes:s.session.allNodes,event:o}),o.preventSigmaDefault()),n.emit("moveBody",{event:o,preventSigmaDefault:function(){return o.preventSigmaDefault()}})},e.handleLeave=function(i){var o=et(i),s={event:o,preventSigmaDefault:function(){return o.preventSigmaDefault()}};n.hoverResolver.pointerLeft(),To(n,null,o),n.emit("leaveStage",s)},e.handleEnter=function(i){var o=et(i);n.emit("enterStage",{event:o,preventSigmaDefault:function(){return o.preventSigmaDefault()}})};var r=function(o){return function(s){var l=et(s),u={event:l,preventSigmaDefault:function(){return l.preventSigmaDefault()}},d=Tr(n,l,o);if(d){n.emit(on(d.kind,o),sn(d,u));return}n.emit("".concat(o,"Stage"),u)}};e.handleClick=r("click"),e.handleRightClick=r("rightClick"),e.handleDoubleClick=r("doubleClick"),e.handleWheel=r("wheel"),e.handleDown=function(i){var o=et(i),s={event:o,preventSigmaDefault:function(){return o.preventSigmaDefault()}},l=Tr(n,o,"down");if(l){l.kind==="node"&&n.settings.enableNodeDrag&&(n.dragManager.pendingNode=l.key),n.emit(on(l.kind,"down"),sn(l,s));return}n.emit("downStage",s)},e.handleUp=function(i){var o=et(i),s={event:o,preventSigmaDefault:function(){return o.preventSigmaDefault()}},l=n.dragManager.end();l&&n.emit("nodeDragEnd",O({node:l.node,allDraggedNodes:l.allNodes},s));var u=Tr(n,o,"up");if(u){n.emit(on(u.kind,"up"),sn(u,s));return}n.emit("upStage",s)},a.on("mousemove",e.handleMove),a.on("mousemovebody",e.handleMoveBody),a.on("click",e.handleClick),a.on("rightClick",e.handleRightClick),a.on("doubleClick",e.handleDoubleClick),a.on("wheel",e.handleWheel),a.on("mousedown",e.handleDown),a.on("mouseup",e.handleUp),a.on("mouseleave",e.handleLeave),a.on("mouseenter",e.handleEnter),t.on("touchdown",e.handleDown),t.on("touchdown",e.handleMove),t.on("touchup",e.handleUp),t.on("touchmove",e.handleMove),t.on("tap",e.handleClick),t.on("doubletap",e.handleDoubleClick),t.on("touchmove",e.handleMoveBody)}function _u(n,a){var t=n.graph,e=new Set(["x","y","zIndex","type"]);a.eachNodeAttributesUpdatedGraphUpdate=function(r){var i,o=(i=r.hints)===null||i===void 0?void 0:i.attributes,s=!o||o.some(function(l){return e.has(l)});n.refresh({partialGraph:{nodes:t.nodes()},skipIndexation:!s,schedule:!0})},a.eachEdgeAttributesUpdatedGraphUpdate=function(r){var i,o=(i=r.hints)===null||i===void 0?void 0:i.attributes,s=o&&["zIndex","type"].some(function(l){return o?.includes(l)});n.refresh({partialGraph:{edges:t.edges()},skipIndexation:!s,schedule:!0})},a.addNodeGraphUpdate=function(r){n.addNode(r.key),n.refresh({partialGraph:{nodes:[r.key]},skipIndexation:!1,schedule:!0})},a.updateNodeGraphUpdate=function(r){n.refresh({partialGraph:{nodes:[r.key]},skipIndexation:!1,schedule:!0})},a.dropNodeGraphUpdate=function(r){n.removeNode(r.key),n.refresh({schedule:!0})},a.addEdgeGraphUpdate=function(r){var i=r.key;n.edgeGroups.register(i),n.addEdge(i);var o=n.edgeGroups.getSiblings(i),s=G(o),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;n.addEdge(u)}}catch(d){s.e(d)}finally{s.f()}n.refresh({partialGraph:{edges:[i].concat(H(o))},schedule:!0})},a.updateEdgeGraphUpdate=function(r){n.refresh({partialGraph:{edges:[r.key]},skipIndexation:!1,schedule:!0})},a.dropEdgeGraphUpdate=function(r){var i=r.key,o=n.edgeGroups.getSiblings(i);n.edgeGroups.unregister(i),n.removeEdge(i);var s=G(o),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;n.addEdge(u)}}catch(d){s.e(d)}finally{s.f()}n.refresh({schedule:!0})},a.clearEdgesGraphUpdate=function(){n.clearEdgeState(),n.clearEdgeIndices(),n.refresh({schedule:!0})},a.clearGraphUpdate=function(){n.clearEdgeState(),n.clearNodeState(),n.clearEdgeIndices(),n.clearNodeIndices(),n.refresh({schedule:!0})},t.on("nodeAdded",a.addNodeGraphUpdate),t.on("nodeDropped",a.dropNodeGraphUpdate),t.on("nodeAttributesUpdated",a.updateNodeGraphUpdate),t.on("eachNodeAttributesUpdated",a.eachNodeAttributesUpdatedGraphUpdate),t.on("edgeAdded",a.addEdgeGraphUpdate),t.on("edgeDropped",a.dropEdgeGraphUpdate),t.on("edgeAttributesUpdated",a.updateEdgeGraphUpdate),t.on("eachEdgeAttributesUpdated",a.eachEdgeAttributesUpdatedGraphUpdate),t.on("edgesCleared",a.clearEdgesGraphUpdate),t.on("cleared",a.clearGraphUpdate)}function Tu(n,a){n.removeListener("nodeAdded",a.addNodeGraphUpdate),n.removeListener("nodeDropped",a.dropNodeGraphUpdate),n.removeListener("nodeAttributesUpdated",a.updateNodeGraphUpdate),n.removeListener("eachNodeAttributesUpdated",a.eachNodeAttributesUpdatedGraphUpdate),n.removeListener("edgeAdded",a.addEdgeGraphUpdate),n.removeListener("edgeDropped",a.dropEdgeGraphUpdate),n.removeListener("edgeAttributesUpdated",a.updateEdgeGraphUpdate),n.removeListener("eachEdgeAttributesUpdated",a.eachEdgeAttributesUpdatedGraphUpdate),n.removeListener("edgesCleared",a.clearEdgesGraphUpdate),n.removeListener("cleared",a.clearGraphUpdate)}var Su={x:.5,y:.5,angle:0,ratio:1},Eu=8,Ru=.001;function Au(n){var a=n.coords,t=n.nodeData,e=n.dimensions,r=n.stagePadding,i=n.zoomToSizeRatioFunction,o=n.itemSizesReference,s=n.fitLabels,l=n.nodeLabelBox,u=Object.keys(a);if(!u.length)return n.extent;for(var d=i(1)||1,c=o==="positions",p=e.width,v=e.height,f=n.extent,b=0;b<Eu;b++){for(var g=pt(f),h={width:f.x[1]-f.x[0]||1,height:f.y[1]-f.y[0]||1},m=be(Su,e,h,r),x=lo(m,g({x:0,y:0}),p,v),y=lo(m,g({x:1,y:0}),p,v),_=Math.hypot(y.x-x.x,y.y-x.y)||1,T=1/0,R=-1/0,E=1/0,D=-1/0,P=0,w=u.length;P<w;P++){var A=u[P],F=t[A],L=F.size/d*(c?_:1),k=-L,N=L,z=-L,I=L;if(s){var C=l(F,L);C&&(C.minX<k&&(k=C.minX),C.maxX>N&&(N=C.maxX),C.minY<z&&(z=C.minY),C.maxY>I&&(I=C.maxY))}var M=a[A],W=M.x,B=M.y;T=Math.min(T,W+k/_),R=Math.max(R,W+N/_),E=Math.min(E,B-I/_),D=Math.max(D,B-z/_)}var U={x:[T,R],y:[E,D]},V=Math.max(U.x[1]-U.x[0],U.y[1]-U.y[0])||1,K=Math.max(Math.abs(U.x[0]-f.x[0]),Math.abs(U.x[1]-f.x[1]),Math.abs(U.y[0]-f.y[0]),Math.abs(U.y[1]-f.y[1]));if(f=U,K/V<Ru)break}return f}function lo(n,a,t,e){var r=we(n,a);return{x:(1+r.x)*t/2,y:(1-r.y)*e/2}}var Du=typeof navigator<"u"&&/Mac|iP(hone|ad|od)/.test(navigator.platform),Cu=1500,Lu=`.sigma-gesture-hint {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 1em;
  background: #00000066;
  color: #ffffff;
  font-size: 1em;
  pointer-events: none;
  transition: opacity 0.1s;
}`;function uo(n){var a,t,e=Ne("style");e.textContent=n,document.head.appendChild(e);var r=((a=(t=e.sheet)===null||t===void 0?void 0:t.cssRules.length)!==null&&a!==void 0?a:0)>0;return e.remove(),r}var tt=null;function Pu(){return tt===null&&(tt=Lu,uo("@scope {}")&&(tt=`@scope {
`.concat(tt,`
}`)),uo("@layer sigma-gesture-hint {}")&&(tt=`@layer sigma-gesture-hint {
`.concat(tt,`
}`))),tt}var Fu=(function(){function n(a){X(this,n),S(this,"hideTimeout",null),this.styleElement=Ne("style"),this.styleElement.textContent=Pu(),a.appendChild(this.styleElement),this.element=Ne("div",{opacity:"0"},{class:"sigma-gesture-hint"}),a.appendChild(this.element)}return j(n,[{key:"show",value:function(t,e){var r=this,i=t==="touch"?e.sharedGestureTouchMessage:Du?e.sharedGestureAppleWheelMessage:e.sharedGestureWheelMessage;i&&(this.element.textContent=i,this.element.style.opacity="1",typeof this.hideTimeout=="number"&&clearTimeout(this.hideTimeout),this.hideTimeout=window.setTimeout(function(){r.hideTimeout=null,r.element.style.opacity="0"},Cu))}},{key:"kill",value:function(){typeof this.hideTimeout=="number"&&clearTimeout(this.hideTimeout),this.styleElement.remove(),this.element.remove()}}])})(),wu=(function(){function n(a){X(this,n),S(this,"readBuffer",null),S(this,"fence",null),S(this,"result",new Uint8Array(4)),S(this,"generation",0),S(this,"readGeneration",0),S(this,"lastEvent",null),S(this,"active",!1),S(this,"dirty",!1),S(this,"rafId",null),S(this,"killed",!1),this.options=a}return j(n,[{key:"pointerMoved",value:function(t){this.lastEvent=t,this.active=!0,this.request()}},{key:"pointerLeft",value:function(){this.active=!1,this.dirty=!1}},{key:"frameRendered",value:function(){this.request()}},{key:"invalidate",value:function(){this.generation++}},{key:"request",value:function(){if(!(this.killed||!this.active||!this.lastEvent)){if(this.fence){this.dirty=!0;return}this.startRead()}}},{key:"startRead",value:function(){var t=this.options,e=t.gl,r=t.getFrameBuffer,i=t.getPixelRatio,o=t.getDownSizingRatio;this.readGeneration=this.generation;var s=this.lastEvent,l=Ft(e,s.x,s.y,i(),o()),u=Z(l,2),d=u[0],c=u[1];this.readBuffer||(this.readBuffer=e.createBuffer()),e.bindFramebuffer(e.FRAMEBUFFER,r()),e.bindBuffer(e.PIXEL_PACK_BUFFER,this.readBuffer),e.bufferData(e.PIXEL_PACK_BUFFER,4,e.STREAM_READ),e.readPixels(d,c,1,1,e.RGBA,e.UNSIGNED_BYTE,0),e.bindBuffer(e.PIXEL_PACK_BUFFER,null),e.bindFramebuffer(e.FRAMEBUFFER,null),this.fence=e.fenceSync(e.SYNC_GPU_COMMANDS_COMPLETE,0),e.flush(),this.schedulePoll(s)}},{key:"schedulePoll",value:function(t){var e=this;this.rafId=requestAnimationFrame(function(){e.rafId=null,e.poll(t)})}},{key:"poll",value:function(t){var e=this.options,r=e.gl,i=e.onIndex;if(!(this.killed||!this.fence)){var o=r.clientWaitSync(this.fence,0,0);if(o===r.TIMEOUT_EXPIRED){this.schedulePoll(t);return}if(r.deleteSync(this.fence),this.fence=null,o!==r.WAIT_FAILED&&this.readGeneration===this.generation){r.bindBuffer(r.PIXEL_PACK_BUFFER,this.readBuffer),r.getBufferSubData(r.PIXEL_PACK_BUFFER,0,this.result),r.bindBuffer(r.PIXEL_PACK_BUFFER,null);var s=Z(this.result,4),l=s[0],u=s[1],d=s[2],c=s[3];this.active&&i(wt(l,u,d,c),t)}this.dirty&&(this.dirty=!1,this.active&&this.lastEvent&&this.startRead())}}},{key:"reset",value:function(){this.rafId!==null&&cancelAnimationFrame(this.rafId),this.rafId=null,this.fence=null,this.readBuffer=null,this.dirty=!1}},{key:"kill",value:function(){this.killed=!0,this.rafId!==null&&cancelAnimationFrame(this.rafId),this.rafId=null;var t=this.options.gl;this.fence&&t.deleteSync(this.fence),this.fence=null,this.readBuffer&&t.deleteBuffer(this.readBuffer),this.readBuffer=null}}])})(),co=(function(){function n(a,t){X(this,n),this.key=a,this.size=t}return j(n,null,[{key:"compare",value:function(t,e){return t.size>e.size?-1:t.size<e.size||t.key>e.key?1:-1}}])})(),ta=(function(){function n(){X(this,n),S(this,"width",0),S(this,"height",0),S(this,"cellSize",0),S(this,"columns",0),S(this,"rows",0),S(this,"cells",{})}return j(n,[{key:"resizeAndClear",value:function(t,e){this.width=t.width,this.height=t.height,this.cellSize=e,this.columns=Math.ceil(t.width/e),this.rows=Math.ceil(t.height/e),this.cells={}}},{key:"getIndex",value:function(t){var e=Math.floor(t.x/this.cellSize),r=Math.floor(t.y/this.cellSize);return r*this.columns+e}},{key:"add",value:function(t,e,r){var i=new co(t,e),o=this.getIndex(r),s=this.cells[o];s||(s=[],this.cells[o]=s),s.push(i)}},{key:"organize",value:function(){for(var t in this.cells){var e=this.cells[t];e.sort(co.compare)}}},{key:"getLabelsToDisplay",value:function(t,e,r){var i=this.cellSize*this.cellSize,o=i/t/t,s=o*e/i,l=Math.ceil(s),u=[];if(r)for(var d=Math.max(0,Math.floor(r.x1/this.cellSize)),c=Math.min(this.columns-1,Math.floor(r.x2/this.cellSize)),p=Math.max(0,Math.floor(r.y1/this.cellSize)),v=Math.min(this.rows-1,Math.floor(r.y2/this.cellSize)),f=p;f<=v;f++)for(var b=d;b<=c;b++){var g=f*this.columns+b,h=this.cells[g];if(h)for(var m=0;m<Math.min(l,h.length);m++)u.push(h[m].key)}else for(var x in this.cells)for(var y=this.cells[x],_=0;_<Math.min(l,y.length);_++)u.push(y[_].key);return u}}])})();function Iu(n){var a=n.graph,t=n.hoveredNode,e=n.highlightedNodes,r=n.displayedNodeLabels,i=new Set,o=new Set(e);t&&o.add(t);var s=G(o),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;a.hasNode(u)&&a.forEachEdge(u,function(v){i.add(v)})}}catch(v){s.e(v)}finally{s.f()}var d=G(r),c;try{var p=function(){var f=c.value;if(o.has(f))return 1;a.forEachEdge(f,function(b,g,h,m){var x=h===f?m:h;r.has(x)&&i.add(b)})};for(d.s();!(c=d.n()).done;)p()}catch(v){d.e(v)}finally{d.f()}return Array.from(i)}var Rt=150,At=50,ku={both:0,node:1,label:2},zu={over:0,above:1,below:2,auto:3},ho=12,Nu=3,Mu=(function(){function n(a){X(this,n),S(this,"labelGrid",new ta),S(this,"edgeAnchorGrid",new ta),S(this,"displayedNodeLabels",new Set),S(this,"displayedEdgeLabels",new Set),S(this,"edgeLabelCandidates",[]),S(this,"renderedNodeLabels",new Set),S(this,"labelSizeCache",new Map),S(this,"framePassPoints",new Float32Array(0)),S(this,"labelsDirty",!0),this.internals=a}return j(n,[{key:"resetFrame",value:function(){this.displayedNodeLabels=new Set,this.renderedNodeLabels=new Set,this.labelSizeCache.clear()}},{key:"clearEdgeLabels",value:function(){this.displayedEdgeLabels=new Set}},{key:"resetLabelGrid",value:function(){this.labelGrid=new ta,this.edgeAnchorGrid=new ta}},{key:"processWebGLLabels",value:function(t){for(var e,r=this.internals,i=r.labelProgram,o=r.primitives,s=r.nodeDataCache,l=(o==null||(e=o.nodes)===null||e===void 0||(e=e.label)===null||e===void 0||(e=e.font)===null||e===void 0?void 0:e.family)||"sans-serif",u=new Map,d=0,c=t.length;d<c;d++){var p=t[d],v=s[p];if(!(v.visibility==="hidden"||!v.label)){var f=v.labelFont||l,b=u.get(f);b?b.push(v.label):u.set(f,[v.label])}}var g=G(u),h;try{for(g.s();!(h=g.n()).done;){var m=Z(h.value,2),x=m[0],y=m[1],_=bt(x),T=_.family,R=_.weight,E=_.style,D=i.registerFont(T,R,E);i.ensureGlyphsReady(y,D)}}catch(P){g.e(P)}finally{g.f()}}},{key:"measureNodeLabel",value:function(t){var e,r;if(!t.label)return{width:0,height:0,textHeight:0};var i=this.internals,o=i.labelProgram,s=i.primitives,l=(e=t.labelSize)!==null&&e!==void 0?e:14,u=t.labelFont||(s==null||(r=s.nodes)===null||r===void 0||(r=r.label)===null||r===void 0||(r=r.font)===null||r===void 0?void 0:r.family)||"sans-serif",d="".concat(t.label,"|").concat(l,"|").concat(u);if(this.labelSizeCache.has(d))return this.labelSizeCache.get(d);var c=bt(u),p=c.family,v=c.weight,f=c.style,b=o.registerFont(p,v,f),g=o.measureLabel(t.label,l,b);return this.labelSizeCache.set(d,g),g}},{key:"nodeLabelBox",value:function(t,e){var r,i,o,s,l;if(t.visibility==="hidden"||t.labelVisibility==="hidden")return null;var u=this.measureNodeLabel(t),d=u.width,c=u.height,p=u.textHeight;if(!d)return null;var v=(r=(i=this.internals.primitives)===null||i===void 0||(i=i.nodes)===null||i===void 0||(i=i.label)===null||i===void 0?void 0:i.margin)!==null&&r!==void 0?r:Be,f=e+v,b=t.labelBackgroundColor?(o=t.labelBackgroundPadding)!==null&&o!==void 0?o:$t:0,g=d/2,h=c/2,m=g+b,x=h+b,y=p/2,_=0,T=0;switch((s=t.labelPosition)!==null&&s!==void 0?s:"right"){case"left":_=-(f+g);break;case"above":T=-(f+y);break;case"below":T=f+y;break;case"over":break;default:_=f+g}var R=(l=t.labelAngle)!==null&&l!==void 0?l:0,E=Pt({x:_,y:T},R),D=E.x,P=E.y,w=Math.abs(Math.cos(R)),A=Math.abs(Math.sin(R)),F=w*m+A*x,L=A*m+w*x;return{minX:D-F,maxX:D+F,minY:P-L,maxY:P+L}}},{key:"computeDisplayedNodeLabels",value:function(){var t=this.internals.getCameraState(),e=this.internals.getDimensions(),r=e.width,i=e.height,o=this.internals.viewportToFramedGraph({x:-Rt,y:-At}),s=this.internals.viewportToFramedGraph({x:r+Rt,y:-At}),l=this.internals.viewportToFramedGraph({x:-Rt,y:i+At}),u=this.internals.viewportToFramedGraph({x:r+Rt,y:i+At}),d=Math.min(o.x,s.x,l.x,u.x),c=Math.max(o.x,s.x,l.x,u.x),p=Math.min(o.y,s.y,l.y,u.y),v=Math.max(o.y,s.y,l.y,u.y),f=be({x:.5,y:.5,ratio:1,angle:0},{width:r,height:i},this.internals.getGraphDimensions(),this.internals.getStagePadding()),b=function(C){var M=we(f,C);return{x:(1+M.x)*r/2,y:(1-M.y)*i/2}},g=b({x:d,y:p}),h=b({x:c,y:p}),m=b({x:d,y:v}),x=b({x:c,y:v}),y={x1:Math.min(g.x,h.x,m.x,x.x),y1:Math.min(g.y,h.y,m.y,x.y),x2:Math.max(g.x,h.x,m.x,x.x),y2:Math.max(g.y,h.y,m.y,x.y)},_=this.internals,T=_.settings,R=_.nodeDataCache,E=_.nodesWithForcedLabels,D=this.labelGrid.getLabelsToDisplay(t.ratio,T.labelDensity,y);Mt(D,E);for(var P=0,w=D.length;P<w;P++){var A=D[P],F=R[A];if(!this.displayedNodeLabels.has(A)&&!(F.visibility==="hidden"||F.labelVisibility==="hidden")&&F.label&&!(F.x<d||F.x>c||F.y<p||F.y>v)){var L=this.internals.framedGraphToViewport(F),k=L.x,N=L.y,z=this.internals.scaleSize(F.size);!ye(F)&&z<T.labelRenderedSizeThreshold||k<-Rt-z||k>r+Rt+z||N<-At-z||N>i+At+z||this.displayedNodeLabels.add(A)}}}},{key:"buildFramePassPoints",value:function(){var t=this.internals,e=t.nodeDataCache,r=t.nodeDataTexture;if(!r)return{data:this.framePassPoints,count:0};var i=this.displayedNodeLabels.size*3;this.framePassPoints.length<i&&(this.framePassPoints=new Float32Array(i));var o=this.framePassPoints,s=0,l=G(this.displayedNodeLabels),u;try{for(l.s();!(u=l.n()).done;){var d,c,p=u.value,v=e[p];if(v){var f=r.getIndex(p);f<0||(o[s*3]=f,o[s*3+1]=(d=Oe[v.labelPosition||Re.labelPosition])!==null&&d!==void 0?d:0,o[s*3+2]=(c=v.labelAngle)!==null&&c!==void 0?c:0,s++)}}}catch(b){l.e(b)}finally{l.f()}return{data:o,count:s}}},{key:"renderWebGLLabels",value:function(t,e){var r=this.internals,i=r.nodeDataCache,o=r.labelProgram,s=r.primitives,l=r.nodeDataTexture,u=[],d=G(this.displayedNodeLabels),c;try{for(d.s();!(c=d.n()).done;){var p=c.value;if(!this.renderedNodeLabels.has(p)){var v=i[p];e&&v.labelDepth!==e||(this.renderedNodeLabels.add(p),u.push(p))}}}catch(ce){d.e(ce)}finally{d.f()}if(u.length!==0){if(this.labelsDirty){for(var f,b,g,h=0,m=0,x=u.length;m<x;m++){var y=i[u[m]];h+=y.label.length}o.reallocate(h);for(var _=14,T=(f=s==null||(b=s.nodes)===null||b===void 0||(b=b.label)===null||b===void 0?void 0:b.margin)!==null&&f!==void 0?f:Be,R=Re.labelPosition,E=(s==null||(g=s.nodes)===null||g===void 0||(g=g.label)===null||g===void 0||(g=g.font)===null||g===void 0?void 0:g.family)||"sans-serif",D=new Map,P=0,w=0,A=u.length;w<A;w++){var F,L,k,N,z=u[w],I=i[z],C=I.labelFont||E,M=D.get(C);if(M===void 0){var W=bt(C),B=W.family,U=W.weight,V=W.style;M=o.registerFont(B,U,V),D.set(C,M)}var K={text:I.label,x:I.x,y:I.y,size:(F=I.labelSize)!==null&&F!==void 0?F:_,color:I.labelColor,nodeSize:I.size,margin:T,position:(L=I.labelPosition)!==null&&L!==void 0?L:R,hidden:!1,forceLabel:ye(I),type:"default",zIndex:(k=I.zIndex)!==null&&k!==void 0?k:0,parentType:"node",parentKey:z,fontKey:M,labelAngle:(N=I.labelAngle)!==null&&N!==void 0?N:0,nodeIndex:l.getIndex(z)},ee=o.processLabel(z,P,K);P+=ee}o.invalidateBuffers()}o.render(t)}}},{key:"renderBackdrops",value:function(t,e){var r=this.internals,i=r.backdropProgram,o=r.nodeDataCache,s=r.nodesWithBackdrop,l=r.attachmentManager,u=r.pixelRatio,d=r.nodeDataTexture,c=[],p=G(s),v;try{for(p.s();!(v=p.n()).done;){var f,b=v.value,g=o[b];if(!(!g||g.visibility==="hidden")&&!(e&&g.depth!==e)){var h=(f=d?.getIndex(b))!==null&&f!==void 0?f:-1;h<0||c.push({key:b,nodeIndex:h})}}}catch(Xe){p.e(Xe)}finally{p.f()}if(c.length!==0){i.reallocate(c.length);for(var m=0;m<c.length;m++){var x,y,_,T,R,E,D,P,w=c[m],A=w.key,F=w.nodeIndex,L=o[A],k=this.displayedNodeLabels.has(A),N=k?this.measureNodeLabel(L):{width:0,height:0,textHeight:0},z=N.textHeight,I=N.width,C=N.height,M=0,W=0;if(k&&L.labelAttachment&&l){var B=l.getEntry(A,L.labelAttachment);if(B){var U=L.labelAttachmentPlacement||"below";if(U==="below"||U==="above"){var V=B.height/u;C+=V+He,I=Math.max(I,B.width/u),W=U==="below"?(V+He)/2:-(V+He)/2}else{var K=B.width/u;I+=K+He,C=Math.max(C,B.height/u),M=U==="right"?(K+He)/2:-(K+He)/2}}}var ee=L.backdropColor?xe(L.backdropColor):[255,255,255,255],ce=L.backdropShadowColor?xe(L.backdropShadowColor):[0,0,0,128],ge=ee.map(function(Xe){return Xe/255}),Ct=ce.map(function(Xe){return Xe/255}),ln=(x=L.backdropShadowBlur)!==null&&x!==void 0?x:12,it=(y=L.backdropPadding)!==null&&y!==void 0?y:6,Vo=L.backdropBorderColor?xe(L.backdropBorderColor):[0,0,0,0],Xo=Vo.map(function(Xe){return Xe/255}),jo=(_=L.backdropBorderWidth)!==null&&_!==void 0?_:0,qo=(T=L.backdropCornerRadius)!==null&&T!==void 0?T:0,Mr=(R=L.backdropLabelPadding)!==null&&R!==void 0?R:-1,Yo=Mr<0?it:Mr,Ko=(E=ku[(D=L.backdropArea)!==null&&D!==void 0?D:"both"])!==null&&E!==void 0?E:0,Zo={key:A,nodeIndex:F,label:L.label,labelWidth:I,labelHeight:C,textHeight:z,type:"default",position:L.labelPosition||Re.labelPosition,labelAngle:(P=L.labelAngle)!==null&&P!==void 0?P:0,backdropColor:ge,backdropShadowColor:Ct,backdropShadowBlur:ln,backdropPadding:it,backdropBorderColor:Xo,backdropBorderWidth:jo,backdropCornerRadius:qo,backdropLabelPadding:Yo,backdropArea:Ko,labelBoxOffset:[M,W]};i.processBackdrop(m,Zo)}i.invalidateBuffers(),i.render(t)}}},{key:"renderLabelBackgrounds",value:function(t,e){var r=this.internals,i=r.labelBackgroundProgram,o=r.nodeDataCache,s=r.nodeDataTexture,l=ne.nodeLabel.writesPickingThisFrame(this.internals),u=[],d=G(this.displayedNodeLabels),c;try{for(d.s();!(c=d.n()).done;){var p=c.value,v=o[p];!v||v.visibility==="hidden"||e&&v.labelDepth!==e||!l&&!v.labelBackgroundColor||u.push(p)}}catch(F){d.e(F)}finally{d.f()}if(u.length!==0){i.reallocate(u.length);for(var f=0;f<u.length;f++){var b,g,h,m,x=u[f],y=o[x],_=(b=s?.getIndex(x))!==null&&b!==void 0?b:-1;if(!(_<0)){var T=this.measureNodeLabel(y),R=T.width,E=T.height,D=T.textHeight,P=nt(this.internals.pickingState,"nodeLabel",x)||nt(this.internals.pickingState,"node",x),w=y.labelBackgroundColor?ie(y.labelBackgroundColor):ie("transparent"),A={nodeIndex:_,id:Ie(P),color:w,labelWidth:R,labelHeight:E,textHeight:D,positionMode:(g=Oe[y.labelPosition||Re.labelPosition])!==null&&g!==void 0?g:0,labelAngle:(h=y.labelAngle)!==null&&h!==void 0?h:0,padding:(m=y.labelBackgroundPadding)!==null&&m!==void 0?m:$t};i.processLabelBackground(f,A)}}i.invalidateBuffers(),i.render(t)}}},{key:"cacheAttachments",value:function(t){var e=this.internals,r=e.attachmentManager,i=e.pixelRatio,o=e.nodeDataCache,s=e.nodesWithBackdrop,l=e.graph;if(r){var u=G(s),d;try{for(u.s();!(d=u.n()).done;){var c=d.value;if(this.displayedNodeLabels.has(c)){var p=o[c];if(!(!p||p.visibility==="hidden")&&!(t&&p.depth!==t)&&p.labelAttachment){var v=l.getNodeAttributes(c),f=this.measureNodeLabel(p),b=f.width,g=f.height,h={node:c,attributes:v,pixelRatio:i,labelWidth:b,labelHeight:g};r.renderAttachment(c,p.labelAttachment,h)}}}}catch(m){u.e(m)}finally{u.f()}r.regenerateAtlas()}}},{key:"renderAttachments",value:function(t,e){var r=this.internals,i=r.attachmentManager,o=r.attachmentProgram,s=r.nodeDataCache,l=r.nodesWithBackdrop,u=r.pixelRatio,d=r.nodeDataTexture;if(!(!i||!o)){var c=0;o.reallocateAttachments(l.size);var p=G(l),v;try{for(p.s();!(v=p.n()).done;){var f,b,g,h,m=v.value;if(this.displayedNodeLabels.has(m)){var x=s[m];if(!(!x||x.visibility==="hidden")&&!(e&&x.labelDepth!==e)&&x.labelAttachment){var y=i.getEntry(m,x.labelAttachment);if(y){var _=(f=d?.getIndex(m))!==null&&f!==void 0?f:-1;if(!(_<0)){var T=this.measureNodeLabel(x),R=T.width,E=T.height,D=T.textHeight,P=(b=Oi[x.labelAttachmentPlacement||"below"])!==null&&b!==void 0?b:0;o.processAttachment(c,{nodeIndex:_,atlasX:y.x,atlasY:y.y,atlasW:y.width,atlasH:y.height,attachWidth:y.width/u,attachHeight:y.height/u,positionMode:(g=Oe[x.labelPosition||Re.labelPosition])!==null&&g!==void 0?g:0,attachmentPlacement:P,labelWidth:R,labelHeight:E,textHeight:D,labelAngle:(h=x.labelAngle)!==null&&h!==void 0?h:0}),c++}}}}}}catch(w){p.e(w)}finally{p.f()}c!==0&&(o.reallocateAttachments(c),i.bindTexture(Jt),o.invalidateBuffers(),o.render(t))}}},{key:"computeDisplayedEdgeLabels",value:function(){var t=this.internals,e=t.graph,r=t.stateManager,i=t.settings,o=t.edgesWithForcedLabels,s=r.getHighlightedNodes(),l=i.edgeLabelAnchors==="allNodes"?new Set(this.edgeAnchorGrid.getLabelsToDisplay(this.internals.getCameraState().ratio,i.labelDensity)):this.displayedNodeLabels,u=r.hovered,d=Iu({graph:e,hoveredNode:u?.kind==="node"?u.key:null,displayedNodeLabels:l,highlightedNodes:s});Mt(d,o),this.edgeLabelCandidates=d,this.displayedEdgeLabels=new Set}},{key:"filterEdgeLabelsForDepth",value:function(t){for(var e=this.internals,r=e.graph,i=e.nodeDataCache,o=e.edgeDataCache,s=[],l=new Set,u=0,d=this.edgeLabelCandidates.length;u<d;u++){var c=this.edgeLabelCandidates[u];if(!l.has(c)){l.add(c);var p=r.extremities(c),v=i[p[0]],f=i[p[1]],b=o[c];!b||!v||!f||b.visibility==="hidden"||b.labelVisibility==="hidden"||v.visibility==="hidden"||f.visibility==="hidden"||t&&b.labelDepth!==t||b.label&&s.push(c)}}return s}},{key:"renderEdgeLabels",value:function(t,e){var r=this.internals,i=r.graph,o=r.nodeDataCache,s=r.edgeDataCache,l=r.primitives,u=r.edgeLabelProgram,d=r.nodeDataTexture,c=r.edgeDataTexture,p=this.filterEdgeLabelsForDepth(e),v=G(p),f;try{for(v.s();!(f=v.n()).done;){var b=f.value;this.displayedEdgeLabels.add(b)}}catch(K){v.e(K)}finally{v.f()}if(p.length!==0){if(this.labelsDirty){var g,h,m=0,x=G(p),y;try{for(x.s();!(y=x.n()).done;){var _=y.value;m+=s[_].label.length}}catch(K){x.e(K)}finally{x.f()}u.reallocate(m);var T=(g=l==null||(h=l.edges)===null||h===void 0||(h=h.label)===null||h===void 0?void 0:h.margin)!==null&&g!==void 0?g:5,R="over",E=0,D=G(p),P;try{for(D.s();!(P=D.n()).done;){var w,A,F=P.value,L=i.extremities(F),k=L[0],N=L[1],z=o[k],I=o[N],C=s[F],M=d.getIndex(k),W=d.getIndex(N),B=c.getIndex(F),U={text:C.label,x:(z.x+I.x)/2,y:(z.y+I.y)/2,size:ho,color:C.labelColor,nodeSize:0,nodeIndex:-1,margin:T,position:(w=C.labelPosition)!==null&&w!==void 0?w:R,hidden:!1,forceLabel:ye(C),type:"default",zIndex:(A=C.zIndex)!==null&&A!==void 0?A:0,parentType:"edge",parentKey:F,fontKey:"",labelAngle:0,sourceX:z.x,sourceY:z.y,targetX:I.x,targetY:I.y,sourceSize:z.size,targetSize:I.size,sourceShape:z.shape||"circle",targetShape:I.shape||"circle",edgeSize:C.size,offset:0,edgeAttributes:C,sourceNodeIndex:M,targetNodeIndex:W,edgeIndex:B},V=u.processEdgeLabel(F,E,U);E+=V}}catch(K){D.e(K)}finally{D.f()}u.invalidateBuffers()}u.render(t)}}},{key:"renderEdgeLabelBackgrounds",value:function(t,e){var r,i,o=this.internals,s=o.edgeLabelBackgroundProgram,l=o.edgeLabelProgram,u=o.edgeDataCache,d=o.primitives,c=o.edgeDataTexture;if(c){var p=ne.edgeLabel.writesPickingThisFrame(this.internals),v=(r=d==null||(i=d.edges)===null||i===void 0||(i=i.label)===null||i===void 0?void 0:i.margin)!==null&&r!==void 0?r:5,f="over",b=this.filterEdgeLabelsForDepth(e),g=[],h=G(b),m;try{for(h.s();!(m=h.n()).done;){var x=m.value;!p&&!u[x].labelBackgroundColor||g.push(x)}}catch(z){h.e(z)}finally{h.f()}if(g.length!==0){s.reallocate(g.length);for(var y=0;y<g.length;y++){var _,T,R,E=g[y],D=u[E],P=D.label,w=l.measureLabelAtlasWidth(P),A=(_=D.labelPosition)!==null&&_!==void 0?_:f,F=typeof A=="string"&&(T=zu[A])!==null&&T!==void 0?T:0,L=nt(this.internals.pickingState,"edgeLabel",E)||nt(this.internals.pickingState,"edge",E),k=D.labelBackgroundColor?ie(D.labelBackgroundColor):ie("transparent"),N={edgeIndex:c.getIndex(E),baseFontSize:ho,totalTextWidth:w,positionMode:F,margin:v,padding:(R=D.labelBackgroundPadding)!==null&&R!==void 0?R:Nu,color:k,id:Ie(L),edgeAttributes:D};s.processEdgeLabelBackground(y,E,N)}s.invalidateBuffers(),s.render(t)}}}}])})(),Gu=(function(){function n(a,t,e,r){X(this,n),S(this,"nodeStates",new Map),S(this,"edgeStates",new Map),S(this,"hovered",null),S(this,"dirtyNodes",new Set),S(this,"dirtyEdges",new Set),S(this,"graphStateChanged",!1),S(this,"graphStateFlagsDirty",!1),this.scheduleRefresh=a,this.customNodeStateDefaults=t,this.customEdgeStateDefaults=e,this.customGraphStateDefaults=r,this.graphState=La(r)}return j(n,[{key:"getNodeState",value:function(t){t=""+t;var e=this.nodeStates.get(t);return e||(e=ci(this.customNodeStateDefaults),this.nodeStates.set(t,e)),e}},{key:"getEdgeState",value:function(t){t=""+t;var e=this.edgeStates.get(t);return e||(e=hi(this.customEdgeStateDefaults),this.edgeStates.set(t,e)),e}},{key:"getGraphState",value:function(){return this.flushGraphStateFlags(),this.graphState}},{key:"getHighlightedNodes",value:function(){var t=new Set,e=G(this.nodeStates),r;try{for(e.s();!(r=e.n()).done;){var i=Z(r.value,2),o=i[0],s=i[1];s.isHighlighted&&t.add(o)}}catch(l){e.e(l)}finally{e.f()}return t}},{key:"setNodeState",value:function(t,e){t=""+t;var r=this.getNodeState(t);if(ze(r,e)){var i=O(O({},r),e);this.nodeStates.set(t,i),this.dirtyNodes.add(t),this.updateHoveredNodeTracking(t,r,i),this.graphStateFlagsDirty=!0,this.scheduleRefresh()}}},{key:"setEdgeState",value:function(t,e){t=""+t;var r=this.getEdgeState(t);if(ze(r,e)){var i=O(O({},r),e);this.edgeStates.set(t,i),this.dirtyEdges.add(t),this.updateHoveredEdgeTracking(t,r,i),this.graphStateFlagsDirty=!0,this.scheduleRefresh()}}},{key:"setGraphState",value:function(t){if(ze(this.graphState,t)){var e=O(O({},this.graphState),t);e.isIdle=!e.isPanning&&!e.isZooming&&!e.isDragging,this.graphState=e,this.graphStateChanged=!0,this.scheduleRefresh()}}},{key:"setNodesState",value:function(t,e){var r=!1,i=G(t),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;s=""+s;var l=this.getNodeState(s);if(ze(l,e)){var u=O(O({},l),e);this.nodeStates.set(s,u),this.dirtyNodes.add(s),this.updateHoveredNodeTracking(s,l,u),r=!0}}}catch(d){i.e(d)}finally{i.f()}r&&(this.graphStateFlagsDirty=!0,this.scheduleRefresh())}},{key:"setEdgesState",value:function(t,e){var r=!1,i=G(t),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;s=""+s;var l=this.getEdgeState(s);if(ze(l,e)){var u=O(O({},l),e);this.edgeStates.set(s,u),this.dirtyEdges.add(s),this.updateHoveredEdgeTracking(s,l,u),r=!0}}}catch(d){i.e(d)}finally{i.f()}r&&(this.graphStateFlagsDirty=!0,this.scheduleRefresh())}},{key:"removeNode",value:function(t){this.nodeStates.delete(t),this.dirtyNodes.delete(t),this.clearHoveredFor("node",t)}},{key:"removeEdge",value:function(t){this.edgeStates.delete(t),this.dirtyEdges.delete(t),this.clearHoveredFor("edge",t)}},{key:"pruneNodes",value:function(t){var e=G(this.nodeStates.keys()),r;try{for(e.s();!(r=e.n()).done;){var i=r.value;t(i)||this.removeNode(i)}}catch(o){e.e(o)}finally{e.f()}}},{key:"pruneEdges",value:function(t){var e=G(this.edgeStates.keys()),r;try{for(e.s();!(r=e.n()).done;){var i=r.value;t(i)||this.removeEdge(i)}}catch(o){e.e(o)}finally{e.f()}}},{key:"clearNodes",value:function(){this.nodeStates.clear(),this.dirtyNodes.clear(),this.clearHoveredForKinds(_r("node"))}},{key:"clearEdges",value:function(){this.edgeStates.clear(),this.dirtyEdges.clear(),this.clearHoveredForKinds(_r("edge"))}},{key:"resetGraphState",value:function(){this.graphState=La(this.customGraphStateDefaults),this.graphStateChanged=!1,this.graphStateFlagsDirty=!1}},{key:"clearDirtyTracking",value:function(){this.dirtyNodes.clear(),this.dirtyEdges.clear(),this.graphStateChanged=!1}},{key:"setHovered",value:function(t){this.hovered=t}},{key:"clearHoveredFor",value:function(t,e){this.hovered&&this.hovered.key===e&&_r(t).includes(this.hovered.kind)&&(this.hovered=null)}},{key:"clearHoveredForKinds",value:function(t){this.hovered&&t.includes(this.hovered.kind)&&(this.hovered=null)}},{key:"updateGraphStateFromNodes",value:function(){var t,e=!1,r=!1,i=!1,o=G(this.nodeStates),s;try{for(o.s();!(s=o.n()).done;){var l=Z(s.value,2),u=l[1];if(u.isHovered&&(e=!0),u.isHighlighted&&(r=!0),u.isDragged&&(i=!0),e&&r&&i)break}}catch(c){o.e(c)}finally{o.f()}!e&&((t=this.hovered)===null||t===void 0?void 0:t.kind)==="edge"&&(e=!0);var d=!this.graphState.isPanning&&!this.graphState.isZooming&&!i;(this.graphState.hasHovered!==e||this.graphState.hasHighlighted!==r||this.graphState.isDragging!==i||this.graphState.isIdle!==d)&&(this.graphStateChanged=!0),this.graphState=O(O({},this.graphState),{},{hasHovered:e,hasHighlighted:r,isDragging:i,isIdle:d})}},{key:"updateGraphStateFromEdges",value:function(){var t,e=((t=this.hovered)===null||t===void 0?void 0:t.kind)==="node";if(!e){var r=G(this.edgeStates),i;try{for(r.s();!(i=r.n()).done;){var o=Z(i.value,2),s=o[1];if(s.isHovered){e=!0;break}}}catch(l){r.e(l)}finally{r.f()}}this.graphState.hasHovered!==e&&(this.graphStateChanged=!0),this.graphState=O(O({},this.graphState),{},{hasHovered:e})}},{key:"flushGraphStateFlags",value:function(){this.graphStateFlagsDirty&&(this.updateGraphStateFromNodes(),this.updateGraphStateFromEdges(),this.graphStateFlagsDirty=!1)}},{key:"updateHoveredNodeTracking",value:function(t,e,r){var i;if(e.isHovered!==r.isHovered)if(r.isHovered){var o;if(((o=this.hovered)===null||o===void 0?void 0:o.kind)==="node"&&this.hovered.key!==t){var s=this.hovered.key,l=this.getNodeState(s);this.nodeStates.set(s,O(O({},l),{},{isHovered:!1})),this.dirtyNodes.add(s)}this.hovered={kind:"node",key:t}}else((i=this.hovered)===null||i===void 0?void 0:i.kind)==="node"&&this.hovered.key===t&&(this.hovered=null)}},{key:"updateHoveredEdgeTracking",value:function(t,e,r){var i;if(e.isHovered!==r.isHovered)if(r.isHovered){var o;if(((o=this.hovered)===null||o===void 0?void 0:o.kind)==="edge"&&this.hovered.key!==t){var s=this.hovered.key,l=this.getEdgeState(s);this.edgeStates.set(s,O(O({},l),{},{isHovered:!1})),this.dirtyEdges.add(s)}this.hovered={kind:"edge",key:t}}else((i=this.hovered)===null||i===void 0?void 0:i.kind)==="edge"&&this.hovered.key===t&&(this.hovered=null)}}])})(),fo=1,go=2,vo=3,mo=4,So=(function(n){function a(t,e){var r,i,o,s,l,u=arguments.length>2&&arguments[2]!==void 0?arguments[2]:{};X(this,a),l=Q(this,a),S(l,"nodeReducer",null),S(l,"edgeReducer",null),S(l,"stageCanvas",null),S(l,"mouseLayer",null),S(l,"gestureHint",null),S(l,"extraElements",{}),S(l,"webGLContext",null),S(l,"pickingFrameBuffer",null),S(l,"pickingTexture",null),S(l,"pickingDepthBuffer",null),S(l,"activeListeners",{}),S(l,"nodeVariableEntries",[]),S(l,"edgeVariableEntries",[]),S(l,"edgePathsByName",new Map),S(l,"nodeProgramIndex",{}),S(l,"edgeProgramIndex",{}),S(l,"edgeTextureIndexCache",{}),S(l,"nodeGraphCoords",{}),S(l,"nodeExtent",{x:[0,1],y:[0,1]}),S(l,"matrix",re()),S(l,"invMatrix",re()),S(l,"correctionRatio",1),S(l,"frameId",0),S(l,"customBBox",null),S(l,"gpuTimerExt",void 0),S(l,"activeGpuTimerQuery",null),S(l,"pendingGpuTimerQueries",[]),S(l,"normalizationFunction",pt({x:[0,1],y:[0,1]})),S(l,"graphToViewportRatio",1),S(l,"pickingState",fu()),S(l,"prevNodeVisibilities",{}),S(l,"width",0),S(l,"height",0),S(l,"autoRescaleFrozen",!1),S(l,"stylesDeclaration",null),S(l,"resolvedStageStyle",{}),S(l,"renderFrame",null),S(l,"contextLost",!1),S(l,"pendingProcess","full"),S(l,"needToRefreshState",!1),S(l,"checkEdgesEventsFrame",null),S(l,"edgeStyleAnalysis",{dependency:"static",xAttribute:null,yAttribute:null}),S(l,"depthLayers",H(Nt)),S(l,"customLayerPrograms",new Map),S(l,"nodeShapeSlug",null),S(l,"sdfAtlas",null),S(l,"depthRanges",{nodes:{},edges:{}}),S(l,"nodeBaseDepth",{}),S(l,"edgeBaseDepth",{});var d=u.primitives,c=u.styles,p=u.settings,v=p===void 0?{}:p,f=u.nodeReducer,b=u.edgeReducer,g=u.customNodeState,h=u.customEdgeState,m=u.customGraphState;l.stateManager=new Gu(function(){return l.scheduleStateRefresh()},g,h,m);var x=d??bi;l.stylesDeclaration=c?{nodes:(r=c.nodes)!==null&&r!==void 0?r:vt.nodes,edges:(i=c.edges)!==null&&i!==void 0?i:vt.edges,stage:c.stage}:vt,l.nodeReducer=f??null,l.edgeReducer=b??null;var y=Pa(l.stylesDeclaration.nodes);l.nodeReducer&&(y.dependency="graph-state"),l.edgeStyleAnalysis=Pa(l.stylesDeclaration.edges),l.edgeReducer&&(l.edgeStyleAnalysis.dependency="graph-state"),l.stylesDeclaration.stage&&(l.resolvedStageStyle=za(l.stylesDeclaration.stage,l.stateManager.graphState));var _=Ti(v);if(Ln(_),_.enableNodeDrag){var T=y.xAttribute,R=y.yAttribute;if((!T||!R)&&!_.dragPositionToAttributes)throw new Error('Sigma: `enableNodeDrag` is true but position attribute names could not be inferred from styles. Either use attribute bindings for x/y in your node styles (e.g. `x: { attribute: "x" }`), or provide a `dragPositionToAttributes` setting.')}if(Dn(t),!(e instanceof HTMLElement))throw new Error("Sigma: container should be an html element.");l.container=e,l.edgeGroups=new hu(t,function(I,C){for(var M=0;M<I.length;M++){var W=l.stateManager.getEdgeState(I[M]);W.parallelIndex=M,W.parallelCount=C}});var E=new cu(t,l.viewportToGraph.bind(l),l.setNodesState.bind(l),function(I,C){return l.emit(I,C)});if(l.depthLayers=(o=x.depthLayers)!==null&&o!==void 0?o:H(Nt),!(c!=null&&c.nodes)&&!kt.every(function(I){return l.depthLayers.includes(I)}))throw new Error("Sigma: depthLayers must include ".concat(kt.join(", ")," for the built-in node styles."));if(!(c!=null&&c.edges)&&!zt.every(function(I){return l.depthLayers.includes(I)}))throw new Error("Sigma: depthLayers must include ".concat(zt.join(", ")," for the built-in edge styles."));l.itemBuckets={nodes:new tn(l.depthLayers),edges:new tn(l.depthLayers)},l.initWebGLContext(),l.mouseLayer=Ne("div",{position:"absolute",touchAction:"none",userSelect:"none"},{class:"sigma-mouse"}),l.container.appendChild(l.mouseLayer),l.resolvedStageStyle.background&&(l.container.style.backgroundColor=l.resolvedStageStyle.background),l.resolvedStageStyle.cursor&&(l.container.style.cursor=l.resolvedStageStyle.cursor);var D=new Jn(l.webGLContext),P=new nn(l.webGLContext,{channels:1}),w=new ea(l.webGLContext),A=new nn(l.webGLContext,{channels:4}),F=l.webGLContext,L=new wu({gl:F,getFrameBuffer:function(){return l.pickingFrameBuffer},getPixelRatio:function(){return l.internals.pixelRatio},getDownSizingRatio:function(){return l.internals.settings.pickingDownSizingRatio},onIndex:function(C,M){var W;return To(l.internals,(W=l.pickingState.lookup[C])!==null&&W!==void 0?W:null,M)}}),k=l.initPrograms(x,_),N=x==null||(s=x.nodes)===null||s===void 0?void 0:s.labelAttachments,z=null;return N&&Object.keys(N).length>0&&(z=new Qn(F,N,function(){return l.scheduleRender()})),l.internals=O(O({nodeDataCache:{},edgeDataCache:{},nodesWithForcedLabels:new Set,nodesWithBackdrop:new Set,edgesWithForcedLabels:new Set,settings:_,primitives:x,pixelRatio:$e(),graph:t,stateManager:l.stateManager,dragManager:E,hoverResolver:L,nodeStyleAnalysis:y,pickingState:l.pickingState},k),{},{attachmentManager:z,nodeDataTexture:D,nodeFrameTexture:P,edgeDataTexture:w,edgeFrameTexture:A,getDimensions:function(){return l.getDimensions()},getGraphDimensions:function(){return l.getGraphDimensions()},getStagePadding:function(){return l.getStagePadding()},getCameraState:function(){return l.camera.getState()},getHitAtPosition:function(C){return l.getHitAtPosition(C)},setNodeState:function(C,M){return l.setNodeState(C,M)},setEdgeState:function(C,M){return l.setEdgeState(C,M)},updateContainerCursor:function(){return l.updateContainerCursor()},scheduleRefresh:function(){return l.scheduleRefresh()},viewportToFramedGraph:function(C){return l.viewportToFramedGraph(C)},viewportToGraph:function(C){return l.viewportToGraph(C)},framedGraphToViewport:function(C){return l.framedGraphToViewport(C)},scaleSize:function(C){return l.scaleSize(C)},emit:function(C,M){return l.emit(C,M)}}),l.labelRenderer=new Mu(l.internals),l.resize(),l.initializeWebGLLabels(),l.camera=new Sr,l.bindCameraHandlers(),l.mouseCaptor=new xo(l.mouseLayer,l),l.mouseCaptor.setSettings(l.internals.settings),l.touchCaptor=new yo(l.mouseLayer,l),l.touchCaptor.setSettings(l.internals.settings),l.bindEventHandlers(),l.bindGraphHandlers(),l.handleSettingsUpdate(),l.refresh(),l}return J(a,n),j(a,[{key:"initializeWebGLLabels",value:function(){this.sdfAtlas=new Ce,this.sdfAtlas.registerFont({family:"sans-serif",weight:"normal",style:"normal"})}},{key:"resetWebGLTexture",value:function(){var e=this.webGLContext;if(!this.pickingFrameBuffer)return this;var r=Math.ceil(this.width*this.internals.pixelRatio/this.internals.settings.pickingDownSizingRatio),i=Math.ceil(this.height*this.internals.pixelRatio/this.internals.settings.pickingDownSizingRatio);e.bindFramebuffer(e.FRAMEBUFFER,this.pickingFrameBuffer),this.pickingTexture&&e.deleteTexture(this.pickingTexture);var o=e.createTexture();o&&(e.bindTexture(e.TEXTURE_2D,o),e.texImage2D(e.TEXTURE_2D,0,e.RGBA,r,i,0,e.RGBA,e.UNSIGNED_BYTE,null),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_MIN_FILTER,e.NEAREST),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_MAG_FILTER,e.NEAREST),e.framebufferTexture2D(e.FRAMEBUFFER,e.COLOR_ATTACHMENT0,e.TEXTURE_2D,o,0),this.pickingTexture=o),this.pickingDepthBuffer&&e.deleteRenderbuffer(this.pickingDepthBuffer);var s=e.createRenderbuffer();return s&&(e.bindRenderbuffer(e.RENDERBUFFER,s),e.renderbufferStorage(e.RENDERBUFFER,e.DEPTH_COMPONENT16,r,i),e.framebufferRenderbuffer(e.FRAMEBUFFER,e.DEPTH_ATTACHMENT,e.RENDERBUFFER,s),this.pickingDepthBuffer=s),e.bindFramebuffer(e.FRAMEBUFFER,null),this}},{key:"bindCameraHandlers",value:function(){var e=this;return this.activeListeners.camera=function(){e.refreshMatrices(),e.labelRenderer.labelsDirty=!0,e.scheduleRender()},this.activeListeners.cameraAnimationStart=function(r){var i=r.from,o=r.to;i.ratio!==o.ratio&&e.stateManager.setGraphState({isZooming:!0})},this.activeListeners.cameraAnimationEnd=function(){e.stateManager.setGraphState({isZooming:!1})},this.camera.on("updated",this.activeListeners.camera),this.camera.on("animationStart",this.activeListeners.cameraAnimationStart),this.camera.on("animationEnd",this.activeListeners.cameraAnimationEnd),this}},{key:"unbindCameraHandlers",value:function(){return this.camera.removeListener("updated",this.activeListeners.camera),this.camera.removeListener("animationStart",this.activeListeners.cameraAnimationStart),this.camera.removeListener("animationEnd",this.activeListeners.cameraAnimationEnd),this}},{key:"getHitAtPosition",value:function(e){var r;if(this.contextLost)return null;var i=this.webGLContext;i.bindFramebuffer(i.FRAMEBUFFER,this.pickingFrameBuffer);var o=vn(i,this.pickingFrameBuffer,e.x,e.y,this.internals.pixelRatio,this.internals.settings.pickingDownSizingRatio),s=wt.apply(void 0,H(o));return(r=this.pickingState.lookup[s])!==null&&r!==void 0?r:null}},{key:"bindEventHandlers",value:function(){return yu(this.internals,this.mouseCaptor,this.touchCaptor,this.activeListeners),this}},{key:"bindGraphHandlers",value:function(){return _u({graph:this.internals.graph,edgeGroups:this.edgeGroups,addNode:this.addNode.bind(this),updateNode:this.updateNode.bind(this),removeNode:this.removeNode.bind(this),addEdge:this.addEdge.bind(this),updateEdge:this.updateEdge.bind(this),removeEdge:this.removeEdge.bind(this),clearEdgeState:this.clearEdgeState.bind(this),clearNodeState:this.clearNodeState.bind(this),clearEdgeIndices:this.clearEdgeIndices.bind(this),clearNodeIndices:this.clearNodeIndices.bind(this),refresh:this.refresh.bind(this)},this.activeListeners),this}},{key:"unbindGraphHandlers",value:function(){Tu(this.internals.graph,this.activeListeners)}},{key:"getNodeShapeId",value:function(e){return this.internals.nodeShapeMap&&this.internals.nodeGlobalShapeIds&&e.shape&&e.shape in this.internals.nodeShapeMap?this.internals.nodeGlobalShapeIds[this.internals.nodeShapeMap[e.shape]]:Qe(e.shape||"circle")}},{key:"processNodes",value:function(){var e=this,r=this.internals.graph,i=this.internals.settings,o=this.getDimensions(),s=i.autoRescale,l=i.autoRescaleContent,u=this.nodeExtent;if(s===!1){var d=o.width,c=o.height;u={x:[-d/2,d/2],y:[-c/2,c/2]}}else(s!=="once"||!this.autoRescaleFrozen)&&(u=this.computeNodeExtent(),l!=="positions"&&!this.customBBox&&(u=Au({extent:u,coords:this.nodeGraphCoords,nodeData:this.internals.nodeDataCache,dimensions:o,stagePadding:this.getStagePadding(),zoomToSizeRatioFunction:i.zoomToSizeRatioFunction,itemSizesReference:i.itemSizesReference,fitLabels:l==="labels",nodeLabelBox:function(W,B){return e.labelRenderer.nodeLabelBox(W,B)}})),s==="once"&&(this.autoRescaleFrozen=!0));this.nodeExtent=u,this.normalizationFunction=pt(this.customBBox||this.nodeExtent);var p=new Sr,v=be(p.getState(),o,this.getGraphDimensions(),this.getStagePadding());this.labelRenderer.labelGrid.resizeAndClear(o,i.labelGridCellSize),this.labelRenderer.edgeAnchorGrid.resizeAndClear(o,i.labelGridCellSize);var f=i.renderEdgeLabels&&i.edgeLabelAnchors==="allNodes",b=!1;yr(this.pickingState,"node");for(var g=r.nodes(),h=0,m=g.length;h<m;h++){var x=g[h],y=this.internals.nodeDataCache[x],_=this.nodeGraphCoords[x];y.x=_.x,y.y=_.y,this.normalizationFunction.applyTo(y),y.visibility!==this.prevNodeVisibilities[x]&&(b=!0),typeof y.label=="string"&&y.visibility!=="hidden"&&y.labelVisibility!=="hidden"&&this.labelRenderer.labelGrid.add(x,y.size,this.framedGraphToViewport(y,{matrix:v})),f&&y.visibility!=="hidden"&&this.labelRenderer.edgeAnchorGrid.add(x,y.size,this.framedGraphToViewport(y,{matrix:v}))}this.labelRenderer.labelGrid.organize(),this.labelRenderer.edgeAnchorGrid.organize(),this.nodeProgram.reallocate(g.length);var T=0;this.depthRanges.nodes={},this.nodeBaseDepth={};var R=this.internals.nodeDataCache,E=G(this.depthLayers),D;try{for(E.s();!(D=E.n()).done;){var P=D.value,w=this.itemBuckets.nodes.getSorted(P,function(M){return R[M].zIndex});if(w.length!==0){this.depthRanges.nodes[P]=[{offset:T,count:w.length}];var A=G(w),F;try{for(A.s();!(F=A.n()).done;){var L=F.value;this.nodeBaseDepth[L]=P,this.nodeProgram.allocateNode(L),oo(this.pickingState,"node",L),this.addNodeToProgram(L,T++)}}catch(M){A.e(M)}finally{A.f()}}}}catch(M){E.e(M)}finally{E.f()}this.nodeProgram.invalidateBuffers();for(var k=0,N=g.length;k<N;k++)this.prevNodeVisibilities[g[k]]=this.internals.nodeDataCache[g[k]].visibility;this.labelRenderer.processWebGLLabels(g);var z=G(this.customLayerPrograms.values()),I;try{for(z.s();!(I=z.n()).done;){var C=I.value.program;C.cacheData&&C.cacheData()}}catch(M){z.e(M)}finally{z.f()}return b}},{key:"processEdges",value:function(){var e=this.internals.graph,r=e.edges();this.edgeProgram.reallocate(r.length);var i=0;yr(this.pickingState,"edge"),this.depthRanges.edges={},this.edgeBaseDepth={};var o=this.internals.edgeDataCache,s=G(this.depthLayers),l;try{for(s.s();!(l=s.n()).done;){var u=l.value,d=this.itemBuckets.edges.getSorted(u,function(f){return o[f].zIndex});if(d.length!==0){this.depthRanges.edges[u]=[{offset:i,count:d.length}];var c=G(d),p;try{for(c.s();!(p=c.n()).done;){var v=p.value;this.edgeBaseDepth[v]=u,oo(this.pickingState,"edge",v),this.addEdgeToProgram(v,i++)}}catch(f){c.e(f)}finally{c.f()}}}}catch(f){s.e(f)}finally{s.f()}this.edgeProgram.invalidateBuffers()}},{key:"updateNodeDepthRanges",value:function(e,r,i){var o=this.nodeProgramIndex[e];o!==void 0&&(Bt(this.depthRanges.nodes,r,o),Wt(this.depthRanges.nodes,i,o))}},{key:"updateEdgeDepthRanges",value:function(e,r,i){var o=this.edgeProgramIndex[e];o!==void 0&&(Bt(this.depthRanges.edges,r,o),Wt(this.depthRanges.edges,i,o))}},{key:"handleSettingsUpdate",value:function(){var e=this,r=this.internals.settings;return this.camera.minRatio=r.minCameraRatio,this.camera.maxRatio=r.maxCameraRatio,this.camera.enabledZooming=r.enableCameraZooming,this.camera.enabledPanning=r.enableCameraPanning,this.camera.enabledRotation=r.enableCameraRotation,r.cameraPanBoundaries?this.camera.constrainState=function(i){return e.cleanCameraState(i,r.cameraPanBoundaries&&q(r.cameraPanBoundaries)==="object"?r.cameraPanBoundaries:{})}:this.camera.constrainState=null,this.camera.setState(this.camera.getState()),this.mouseLayer.style.touchAction=r.gestureTarget==="graph"?"none":r.gestureTarget==="shared"?"pan-x pan-y":"auto",r.gestureTarget!=="shared"&&this.gestureHint&&(this.gestureHint.kill(),this.gestureHint=null),this.mouseCaptor.setSettings(this.internals.settings),this.touchCaptor.setSettings(this.internals.settings),this}},{key:"cleanCameraState",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},i=r.tolerance,o=i===void 0?0:i,s=r.boundaries,l=O({},e),u=s||this.nodeExtent,d=Z(u.x,2),c=d[0],p=d[1],v=Z(u.y,2),f=v[0],b=v[1],g=[this.graphToViewport({x:c,y:f},{cameraState:e}),this.graphToViewport({x:p,y:f},{cameraState:e}),this.graphToViewport({x:c,y:b},{cameraState:e}),this.graphToViewport({x:p,y:b},{cameraState:e})],h=1/0,m=-1/0,x=1/0,y=-1/0;g.forEach(function(L){var k=L.x,N=L.y;h=Math.min(h,k),m=Math.max(m,k),x=Math.min(x,N),y=Math.max(y,N)});var _=m-h,T=y-x,R=this.getDimensions(),E=R.width,D=R.height,P=0,w=0;if(_>=E?m<E-o?P=m-(E-o):h>o&&(P=h-o):m>E+o?P=m-(E+o):h<-o&&(P=h+o),T>=D?y<D-o?w=y-(D-o):x>o&&(w=x-o):y>D+o?w=y-(D+o):x<-o&&(w=x+o),P||w){var A=this.viewportToFramedGraph({x:0,y:0},{cameraState:e}),F=this.viewportToFramedGraph({x:P,y:w},{cameraState:e});P=F.x-A.x,w=F.y-A.y,l.x+=P,l.y+=w}return l}},{key:"refreshMatrices",value:function(){var e=this.camera.getState(),r=this.getDimensions(),i=this.getGraphDimensions(),o=this.getStagePadding();this.matrix=be(e,r,i,o),this.invMatrix=be(e,r,i,o,!0),this.correctionRatio=gn(this.matrix,e,r),this.graphToViewportRatio=this.getGraphToViewportRatio()}},{key:"processData",value:function(){var e;this.emit("beforeProcess"),(e=this.internals.attachmentManager)===null||e===void 0||e.clear();var r=O({},this.pickingState.idsByKind),i=this.processNodes();(this.pendingProcess==="full"||i)&&this.processEdges(),gu(this.pickingState,this.internals),vu(r,this.pickingState.idsByKind)||this.internals.hoverResolver.invalidate(),this.pendingProcess="none",this.emit("afterProcess")}},{key:"render",value:function(){var e=this;if(this.contextLost)return this;this.emit("beforeRender");var r=function(){return e.internals.hoverResolver.frameRendered(),e.emit("afterRender"),e};if(this.renderFrame&&(cancelAnimationFrame(this.renderFrame),this.renderFrame=null),this.resize(),(this.pendingProcess!=="none"||this.needToRefreshState)&&(this.labelRenderer.labelsDirty=!0),this.pendingProcess!=="none"&&this.processData(),this.needToRefreshState&&this.refreshState(),this.needToRefreshState=!1,this.stateManager.clearDirtyTracking(),this.pendingProcess!=="none"&&this.processData(),this.clear(),this.resetWebGLTexture(),!this.internals.graph.order)return r();var i=this.mouseCaptor,o=this.camera.isAnimating()||i.isMoving||i.draggedEvents||i.currentWheelDirection;this.refreshMatrices(),this.frameId++;var s=this.internals.settings.DEBUG_logRenderStats?this.getDebugPrograms():null;s&&s.forEach(function(B){return B.resetDebugStats()}),this.internals.settings.DEBUG_gpuTimerQueries&&this.beginGpuTimerQuery(),this.internals.nodeFrameTexture.ensureCapacity(this.internals.nodeDataTexture.getCapacity()),this.internals.edgeFrameTexture.ensureCapacity(this.internals.edgeDataTexture.getCapacity());var l=this.getRenderParams(),u=ne.edge.writesPickingThisFrame(this.internals)?l:O(O({},l),{},{pickingFrameBuffer:null});this.labelRenderer.resetFrame();var d=this.webGLContext,c=Math.ceil(this.width*this.internals.pixelRatio/this.internals.settings.pickingDownSizingRatio),p=Math.ceil(this.height*this.internals.pixelRatio/this.internals.settings.pickingDownSizingRatio);if(d.bindFramebuffer(d.FRAMEBUFFER,this.pickingFrameBuffer),d.viewport(0,0,c,p),d.clear(d.COLOR_BUFFER_BIT|d.DEPTH_BUFFER_BIT),d.bindFramebuffer(d.FRAMEBUFFER,null),d.viewport(0,0,this.width*this.internals.pixelRatio,this.height*this.internals.pixelRatio),d.clear(d.COLOR_BUFFER_BIT|d.DEPTH_BUFFER_BIT),this.internals.nodeDataTexture.upload(),this.internals.edgeDataTexture.upload(),this.nodeProgram.uploadLayerTexture(),this.edgeProgram.uploadAttributeTexture(),this.emit("afterTexturesUpload"),this.internals.nodeDataTexture.bind(vo),this.internals.edgeDataTexture.bind(mo),this.edgeFramePass.run(l,this.internals.edgeFrameTexture,this.internals.edgeDataTexture.getHighWaterMark(),this.edgeProgram.getAttributeTexture(),this.nodeProgram.getAttributeTexture()),this.internals.edgeFrameTexture.bind(fo),this.internals.settings.renderLabels){this.labelRenderer.computeDisplayedNodeLabels();var v=this.labelRenderer.buildFramePassPoints(),f=v.data,b=v.count;this.nodeFramePass.run(f,b,this.internals.nodeFrameTexture,l,this.nodeProgram.getAttributeTexture()),this.internals.nodeFrameTexture.bind(go)}this.internals.settings.renderEdgeLabels&&this.labelRenderer.computeDisplayedEdgeLabels();var g=G(this.customLayerPrograms.values()),h;try{for(g.s();!(h=g.n()).done;){var m=h.value.program;m.preRender&&m.preRender(l)}}catch(B){g.e(B)}finally{g.f()}d.bindFramebuffer(d.FRAMEBUFFER,null),d.viewport(0,0,this.width*this.internals.pixelRatio,this.height*this.internals.pixelRatio),d.blendFunc(d.ONE,d.ONE_MINUS_SRC_ALPHA);var x=!this.internals.settings.hideLabelsOnMove||!o,y=G(this.depthLayers),_;try{for(y.s();!(_=y.n()).done;){var T=_.value,R=G(this.customLayerPrograms.values()),E;try{for(R.s();!(E=R.n()).done;){var D=E.value;D.depth===T&&D.program.render(l)}}catch(B){R.e(B)}finally{R.f()}var P=this.depthRanges.edges[T];if(P&&(!this.internals.settings.hideEdgesOnMove||!o)){var w=G(P),A;try{for(w.s();!(A=w.n()).done;){var F=A.value,L=F.offset,k=F.count;k>0&&this.edgeProgram.render(u,L,k)}}catch(B){w.e(B)}finally{w.f()}}this.internals.settings.renderEdgeLabels&&x&&(this.labelRenderer.renderEdgeLabelBackgrounds(ne.edgeLabel.writesPickingThisFrame(this.internals)?l:O(O({},l),{},{pickingFrameBuffer:null}),T),this.labelRenderer.renderEdgeLabels(l,T)),this.labelRenderer.cacheAttachments(T),this.labelRenderer.renderBackdrops(O(O({},l),{},{pickingFrameBuffer:null}),T);var N=this.depthRanges.nodes[T];if(N){var z=G(N),I;try{for(z.s();!(I=z.n()).done;){var C=I.value,M=C.offset,W=C.count;W>0&&this.nodeProgram.render(l,M,W)}}catch(B){z.e(B)}finally{z.f()}}x&&(this.labelRenderer.renderAttachments(O(O({},l),{},{pickingFrameBuffer:null}),T),this.labelRenderer.renderLabelBackgrounds(ne.nodeLabel.writesPickingThisFrame(this.internals)?l:O(O({},l),{},{pickingFrameBuffer:null}),T),this.internals.settings.renderLabels&&this.labelRenderer.renderWebGLLabels(l,T))}}catch(B){y.e(B)}finally{y.f()}return this.labelRenderer.labelsDirty=!1,this.internals.settings.DEBUG_displayPickingLayer&&(d.bindFramebuffer(d.READ_FRAMEBUFFER,this.pickingFrameBuffer),d.bindFramebuffer(d.DRAW_FRAMEBUFFER,null),d.blitFramebuffer(0,0,c,p,0,0,this.width*this.internals.pixelRatio,this.height*this.internals.pixelRatio,d.COLOR_BUFFER_BIT,d.NEAREST)),this.internals.settings.DEBUG_gpuTimerQueries&&this.endGpuTimerQuery(),this.pollGpuTimerQueries(),s&&this.logRenderStats(s),r()}},{key:"getDebugPrograms",value:function(){return[this.nodeProgram,this.edgeProgram,this.internals.labelProgram,this.internals.edgeLabelProgram,this.internals.edgeLabelBackgroundProgram,this.internals.backdropProgram,this.internals.labelBackgroundProgram,this.internals.attachmentProgram].filter(function(e){return e!==null})}},{key:"logRenderStats",value:function(e){var r={},i=G(e),o;try{for(i.s();!(o=i.n()).done;){var s=o.value;r[s.constructor.name]=O({},s.debugStats)}}catch(l){i.e(l)}finally{i.f()}console.log("[sigma] DEBUG_logRenderStats: frame #".concat(this.frameId)),console.table(r)}},{key:"getGpuTimerExtension",value:function(){return this.gpuTimerExt===void 0&&(this.gpuTimerExt=this.webGLContext.getExtension("EXT_disjoint_timer_query_webgl2"),this.gpuTimerExt||console.warn("Sigma: DEBUG_gpuTimerQueries is enabled, but this browser/driver doesn't support EXT_disjoint_timer_query_webgl2.")),this.gpuTimerExt}},{key:"beginGpuTimerQuery",value:function(){var e=this.getGpuTimerExtension();if(e){var r=this.webGLContext,i=r.createQuery();i&&(r.beginQuery(e.TIME_ELAPSED_EXT,i),this.activeGpuTimerQuery=i)}}},{key:"endGpuTimerQuery",value:function(){!this.gpuTimerExt||!this.activeGpuTimerQuery||(this.webGLContext.endQuery(this.gpuTimerExt.TIME_ELAPSED_EXT),this.pendingGpuTimerQueries.push({query:this.activeGpuTimerQuery,frameId:this.frameId}),this.activeGpuTimerQuery=null)}},{key:"pollGpuTimerQueries",value:function(){if(this.pendingGpuTimerQueries.length!==0){var e=this.webGLContext,r=this.gpuTimerExt;if(!r){this.pendingGpuTimerQueries.forEach(function(c){var p=c.query;return e.deleteQuery(p)}),this.pendingGpuTimerQueries=[];return}var i=e.getParameter(r.GPU_DISJOINT_EXT),o=[],s=G(this.pendingGpuTimerQueries),l;try{for(s.s();!(l=s.n()).done;){var u=l.value;if(!e.getQueryParameter(u.query,e.QUERY_RESULT_AVAILABLE)){o.push(u);continue}if(!i){var d=e.getQueryParameter(u.query,e.QUERY_RESULT);console.log("[sigma] DEBUG_gpuTimerQueries: frame #".concat(u.frameId," GPU time = ").concat((d/1e6).toFixed(2),"ms"))}e.deleteQuery(u.query)}}catch(c){s.e(c)}finally{s.f()}this.pendingGpuTimerQueries=o}}},{key:"postEvaluateNode",value:function(e,r,i){var o=e;o.x===void 0&&(o.x=r.x),o.y===void 0&&(o.y=r.y),e.highlighted=i.isHighlighted;for(var s=0,l=this.nodeVariableEntries.length;s<l;s++){var u,d,c=Z(this.nodeVariableEntries[s],2),p=c[0],v=c[1];o[p]=(u=(d=o[p])!==null&&d!==void 0?d:r[p])!==null&&u!==void 0?u:v.default}}},{key:"addNode",value:function(e){var r=this.internals.graph.getNodeAttributes(e),i=this.stateManager.getNodeState(e),o=this.internals.nodeDataCache[e]||{};if(Ia(this.stylesDeclaration.nodes,r,i,this.stateManager.graphState,this.internals.graph,o),this.postEvaluateNode(o,r,i),this.nodeReducer){var s=this.nodeReducer(e,o,r,i,this.stateManager.graphState,this.internals.graph);o=O(O({},o),s)}if(typeof o.x!="number"||typeof o.y!="number")throw new Error('Sigma: could not find a valid position (x, y) for node "'.concat(e,'". ')+"Provide coordinates via node attributes, styles, or a nodeReducer.");this.internals.nodeShapeMap?(!o.shape||!(o.shape in this.internals.nodeShapeMap))&&(o.shape=Object.keys(this.internals.nodeShapeMap)[0]):this.nodeShapeSlug&&(o.shape=this.nodeShapeSlug),this.internals.nodeDataCache[e]=o,this.nodeGraphCoords[e]={x:o.x,y:o.y},Ae(this.internals.nodesWithForcedLabels,e,ye(o)),Ae(this.internals.nodesWithBackdrop,e,Ot(o)),this.itemBuckets.nodes.set(e,o.depth)}},{key:"updateNode",value:function(e){this.addNode(e);var r=this.internals.nodeDataCache[e];this.normalizationFunction.applyTo(r)}},{key:"removeNode",value:function(e){this.itemBuckets.nodes.remove(e),delete this.internals.nodeDataCache[e],delete this.nodeGraphCoords[e],delete this.nodeProgramIndex[e],this.internals.dragManager.removeNode(e),this.stateManager.removeNode(e),this.internals.nodesWithForcedLabels.delete(e),this.internals.nodesWithBackdrop.delete(e)}},{key:"postEvaluateEdge",value:function(e,r){for(var i=e,o=0,s=this.edgeVariableEntries.length;o<s;o++){var l,u,d=Z(this.edgeVariableEntries[o],2),c=d[0],p=d[1];i[c]=(l=(u=i[c])!==null&&u!==void 0?u:r[c])!==null&&l!==void 0?l:p.default}}},{key:"applyEdgeSpread",value:function(e,r,i){var o;if(!(i.parallelCount<=1)){var s=this.internals.graph.source(e),l=this.internals.graph.target(e),u=s===l,d=u?r.selfLoopPath||r.path:r.parallelPath||r.path,c=d?this.edgePathsByName.get(d):void 0;if(c!=null&&c.spread){var p=(o=r.parallelSpread)!==null&&o!==void 0?o:.25,v=c.spread.compute(i.parallelIndex,i.parallelCount,p);!u&&this.internals.graph.isDirected(e)&&s>l&&(v=-v),r[c.spread.variable]=v}}}},{key:"addEdge",value:function(e){var r=this.internals.graph.getEdgeAttributes(e),i=this.stateManager.getEdgeState(e),o={};if(ka(this.stylesDeclaration.edges,r,i,this.stateManager.graphState,this.internals.graph,o),this.postEvaluateEdge(o,r),this.edgeReducer){var s=this.edgeReducer(e,o,r,i,this.stateManager.graphState,this.internals.graph);o=O(O({},o),s)}this.applyEdgeSpread(e,o,i),this.internals.edgeDataCache[e]=o,Ae(this.internals.edgesWithForcedLabels,e,ye(o)),this.itemBuckets.edges.set(e,o.depth)}},{key:"updateEdge",value:function(e){this.addEdge(e)}},{key:"removeEdge",value:function(e){this.itemBuckets.edges.remove(e),delete this.internals.edgeDataCache[e],delete this.edgeProgramIndex[e],delete this.edgeTextureIndexCache[e],this.internals.edgeDataTexture.free(e),this.stateManager.removeEdge(e),this.internals.edgesWithForcedLabels.delete(e)}},{key:"clearNodeIndices",value:function(){this.labelRenderer.resetLabelGrid(),this.autoRescaleFrozen||(this.nodeExtent={x:[0,1],y:[0,1]}),this.internals.nodeDataCache={},this.nodeGraphCoords={},this.edgeProgramIndex={},this.internals.nodesWithForcedLabels.clear(),this.internals.nodesWithBackdrop.clear(),this.prevNodeVisibilities={},this.itemBuckets.nodes.clearAll(),this.depthRanges.nodes={},this.nodeBaseDepth={}}},{key:"clearEdgeIndices",value:function(){this.internals.edgeDataCache={},this.edgeProgramIndex={},this.edgeTextureIndexCache={},this.internals.edgesWithForcedLabels.clear(),yr(this.pickingState,"edge"),this.itemBuckets.edges.clearAll(),this.depthRanges.edges={},this.edgeBaseDepth={},this.edgeGroups.clear()}},{key:"clearIndices",value:function(){this.clearEdgeIndices(),this.clearNodeIndices()}},{key:"clearNodeState",value:function(){this.labelRenderer.resetFrame(),this.internals.nodesWithBackdrop.clear(),this.internals.dragManager.clear(),this.autoRescaleFrozen=!1,this.stateManager.clearNodes()}},{key:"clearEdgeState",value:function(){this.labelRenderer.clearEdgeLabels(),this.stateManager.clearEdges()}},{key:"clearState",value:function(){this.clearEdgeState(),this.clearNodeState(),this.stateManager.resetGraphState()}},{key:"addNodeToProgram",value:function(e,r){var i,o=this.internals.nodeDataCache[e];this.internals.nodeDataTexture.allocate(e),(i=this.internals.nodeDataTexture).updateNode.apply(i,[e,o.x,o.y,o.size,this.getNodeShapeId(o)].concat(H(mt(o)),[o.color]));var s=this.internals.nodeDataTexture.getIndex(e);this.nodeProgram.process(nt(this.pickingState,"node",e),r,o,s,e),this.nodeProgramIndex[e]=r}},{key:"addEdgeToProgram",value:function(e,r){var i,o,s=this.internals.edgeDataCache[e],l=this.internals.graph.source(e),u=this.internals.graph.target(e),d=this.internals.edgeDataTexture.allocate(e);this.edgeTextureIndexCache[e]=d;var c=l===u,p=!c&&((i=(o=this.stateManager.getEdgeState(e))===null||o===void 0?void 0:o.parallelCount)!==null&&i!==void 0?i:1)>1,v=this.edgeProgram.resolveEdgeIds(s,c,p),f=v.pathId,b=v.headId,g=v.tailId,h=v.headLengthRatio,m=v.tailLengthRatio;this.internals.edgeDataTexture.updateEdge(e,this.internals.nodeDataTexture.getIndex(l),this.internals.nodeDataTexture.getIndex(u),s.size,h,m,f,b,g),this.edgeProgram.process(nt(this.pickingState,"edge",e),r,this.internals.nodeDataCache[l],this.internals.nodeDataCache[u],s,d),this.edgeProgramIndex[e]=r}},{key:"getRenderParams",value:function(){return{frameId:this.frameId,matrix:this.matrix,invMatrix:this.invMatrix,width:this.width,height:this.height,pixelRatio:this.internals.pixelRatio,zoomRatio:this.camera.ratio,cameraAngle:this.camera.angle,sizeRatio:1/this.scaleSize(),correctionRatio:this.correctionRatio,downSizingRatio:this.internals.settings.pickingDownSizingRatio,minEdgeThickness:this.internals.settings.minEdgeThickness,antiAliasingFeather:this.internals.settings.antiAliasingFeather,nodePickingPadding:this.internals.settings.nodePickingPadding,edgePickingPadding:this.internals.settings.edgePickingPadding,labelPickingPadding:this.internals.settings.labelPickingPadding,nodeDataTextureUnit:vo,nodeDataTextureWidth:this.internals.nodeDataTexture.getTextureWidth(),nodeFrameTextureUnit:go,nodeFrameTextureWidth:this.internals.nodeFrameTexture.getTextureWidth(),edgeDataTextureUnit:mo,edgeDataTextureWidth:this.internals.edgeDataTexture.getTextureWidth(),edgeFrameTextureUnit:fo,edgeFrameTextureWidth:this.internals.edgeFrameTexture.getTextureWidth(),pickingFrameBuffer:this.pickingFrameBuffer,labelPixelSnapping:this.internals.settings.labelPixelSnapping?1:0}}},{key:"getStagePadding",value:function(){var e=this.internals.settings,r=e.stagePadding,i=e.autoRescale;return i&&r||0}},{key:"getLayerElement",value:function(e){if(e==="mouse")return this.mouseLayer;var r=this.extraElements[e];if(!r)throw new Error('Sigma: layer "'.concat(e,'" does not exist'));return r}},{key:"initWebGLContext",value:function(){var e=this,r=this.createWebGLContext("stage");this.stageCanvas=this.extraElements.stage,this.webGLContext=r,this.stageCanvas.addEventListener("webglcontextlost",function(i){e.webGLContext&&(i.preventDefault(),e.contextLost=!0,e.renderFrame&&(cancelAnimationFrame(e.renderFrame),e.renderFrame=null),e.gpuTimerExt=void 0,e.activeGpuTimerQuery=null,e.pendingGpuTimerQueries=[],e.emit("webglContextLost"))}),this.stageCanvas.addEventListener("webglcontextrestored",function(){requestAnimationFrame(function(){e.webGLContext&&!e.webGLContext.isContextLost()&&e.restoreWebGLContext()})}),this.initPickingFramebuffer()}},{key:"initPickingFramebuffer",value:function(){var e=this.webGLContext,r=e.createFramebuffer();if(!r)throw new Error("Sigma: cannot create picking frame buffer");e.bindFramebuffer(e.FRAMEBUFFER,r);var i=e.createTexture();if(!i)throw new Error("Sigma: cannot create picking texture");e.bindTexture(e.TEXTURE_2D,i),e.texImage2D(e.TEXTURE_2D,0,e.RGBA,1,1,0,e.RGBA,e.UNSIGNED_BYTE,null),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_MIN_FILTER,e.NEAREST),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_MAG_FILTER,e.NEAREST),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_WRAP_S,e.CLAMP_TO_EDGE),e.texParameteri(e.TEXTURE_2D,e.TEXTURE_WRAP_T,e.CLAMP_TO_EDGE),e.framebufferTexture2D(e.FRAMEBUFFER,e.COLOR_ATTACHMENT0,e.TEXTURE_2D,i,0);var o=e.createRenderbuffer();if(!o)throw new Error("Sigma: cannot create picking depth buffer");if(e.bindRenderbuffer(e.RENDERBUFFER,o),e.renderbufferStorage(e.RENDERBUFFER,e.DEPTH_COMPONENT16,1,1),e.framebufferRenderbuffer(e.FRAMEBUFFER,e.DEPTH_ATTACHMENT,e.RENDERBUFFER,o),e.checkFramebufferStatus(e.FRAMEBUFFER)!==e.FRAMEBUFFER_COMPLETE)throw new Error("Sigma: picking framebuffer is not complete");e.bindFramebuffer(e.FRAMEBUFFER,null),this.pickingFrameBuffer=r,this.pickingTexture=i,this.pickingDepthBuffer=o}},{key:"initPrograms",value:function(e,r){var i=this,o=this.webGLContext,s=Zi(o,this.pickingFrameBuffer,i,e?.nodes,r.antialiasNodes),l=s.nodeProgram,u=s.labelProgram,d=s.backdropProgram,c=s.labelBackgroundProgram,p=s.attachmentProgram,v=s.framePass,f=s.shapeSlug,b=s.shapeNameToIndex,g=s.shapeGlobalIds,h=s.variables;this.nodeProgram=l,this.nodeFramePass=v,this.nodeVariableEntries=Object.entries(h),f&&(this.nodeShapeSlug=f);var m=$i(o,this.pickingFrameBuffer,i,e?.edges,r.antialiasEdges,e?.nodes),x=m.edgeProgram,y=m.labelProgram,_=m.labelBackgroundProgram,T=m.framePass,R=m.variables,E=m.paths;return this.edgeProgram=x,this.edgeFramePass=T,this.edgeVariableEntries=Object.entries(R),this.edgePathsByName=new Map(E.map(function(D){return[D.name,D]})),{labelProgram:u,edgeLabelProgram:y,edgeLabelBackgroundProgram:_,backdropProgram:d,labelBackgroundProgram:c,attachmentProgram:p,nodeShapeMap:b??null,nodeGlobalShapeIds:g??null}}},{key:"restoreWebGLContext",value:function(){var e,r,i,o,s,l=this.internals;this.initPickingFramebuffer(),(e=l.nodeDataTexture)===null||e===void 0||e.restore(),(r=l.nodeFrameTexture)===null||r===void 0||r.restore(),(i=l.edgeDataTexture)===null||i===void 0||i.restore(),(o=l.edgeFrameTexture)===null||o===void 0||o.restore(),(s=l.attachmentManager)===null||s===void 0||s.restore(),l.hoverResolver.reset(),Object.assign(l,this.initPrograms(l.primitives,l.settings));var u=G(this.customLayerPrograms.values()),d;try{for(u.s();!(d=u.n()).done;){var c=d.value;c.program.kill(),c.program=c.factory(this.webGLContext)}}catch(p){u.e(p)}finally{u.f()}this.contextLost=!1,this.emit("webglContextRestored"),this.refresh()}},{key:"createLayer",value:function(e,r){var i=arguments.length>2&&arguments[2]!==void 0?arguments[2]:{};if(this.extraElements[e])throw new Error('Sigma: a layer named "'.concat(e,'" already exists'));var o=Ne(r,{position:"absolute"},{class:"sigma-".concat(e)});return i.style&&Object.assign(o.style,i.style),this.extraElements[e]=o,"beforeLayer"in i&&i.beforeLayer?this.getLayerElement(i.beforeLayer).before(o):"afterLayer"in i&&i.afterLayer?this.getLayerElement(i.afterLayer).after(o):this.container.appendChild(o),o}},{key:"createCanvas",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{};return this.createLayer(e,"canvas",r)}},{key:"createWebGLContext",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},i=this.createCanvas(e,r);r.hidden&&i.remove();var o=i.getContext("webgl2",O({preserveDrawingBuffer:!1,antialias:!1,depth:!0},r));if(!o)throw new Error("Sigma: WebGL 2 is not supported by your browser. Please use a modern browser (Chrome 56+, Firefox 51+, Safari 15+, Edge 79+).");return o.blendFunc(o.ONE,o.ONE_MINUS_SRC_ALPHA),o}},{key:"killLayer",value:function(e){if(e==="stage"||e==="mouse")throw new Error('Sigma: cannot kill built-in layer "'.concat(e,'"'));var r=this.extraElements[e];if(!r)throw new Error("Sigma: cannot kill layer ".concat(e,", which does not exist"));return r.remove(),delete this.extraElements[e],this}},{key:"getWebGLContext",value:function(){if(!this.webGLContext)throw new Error("Sigma: WebGL context is not available");return this.webGLContext}},{key:"getNodeDataTexture",value:function(){if(!this.internals.nodeDataTexture)throw new Error("Sigma: node data texture is not available");return this.internals.nodeDataTexture}},{key:"getNormalizationFunction",value:function(){return this.normalizationFunction}},{key:"addCustomLayerProgram",value:function(e,r,i){var o;if(!this.depthLayers.includes(r))throw new Error('Sigma: cannot add custom layer program at depth "'.concat(r,'", ')+"it must be declared in primitives.depthLayers. Current layers: ".concat(this.depthLayers.join(", ")));return(o=this.customLayerPrograms.get(e))===null||o===void 0||o.program.kill(),this.customLayerPrograms.set(e,{depth:r,factory:i,program:i(this.webGLContext)}),this.refresh(),this}},{key:"removeCustomLayerProgram",value:function(e){var r=this.customLayerPrograms.get(e);return r&&(r.program.kill(),this.customLayerPrograms.delete(e),this.scheduleRender()),this}},{key:"getCamera",value:function(){return this.camera}},{key:"setCamera",value:function(e){return this.camera.cancelAnimation(),this.unbindCameraHandlers(),this.camera=e,this.bindCameraHandlers(),this.scheduleRender(),this}},{key:"getContainer",value:function(){return this.container}},{key:"getGraph",value:function(){return this.internals.graph}},{key:"setGraph",value:function(e){return e===this.internals.graph?this:(this.stateManager.pruneNodes(function(r){return e.hasNode(r)}),this.stateManager.pruneEdges(function(r){return e.hasEdge(r)}),this.unbindGraphHandlers(),this.checkEdgesEventsFrame!==null&&(cancelAnimationFrame(this.checkEdgesEventsFrame),this.checkEdgesEventsFrame=null),this.internals.graph=e,this.autoRescaleFrozen=!1,this.bindGraphHandlers(),this.refresh(),this)}},{key:"getMouseCaptor",value:function(){return this.mouseCaptor}},{key:"getTouchCaptor",value:function(){return this.touchCaptor}},{key:"getDimensions",value:function(){return{width:this.width,height:this.height}}},{key:"getGraphDimensions",value:function(){var e=this.customBBox||this.nodeExtent;return{width:e.x[1]-e.x[0]||1,height:e.y[1]-e.y[0]||1}}},{key:"getNodeDisplayData",value:function(e){var r=this.internals.nodeDataCache[e];return r?Object.assign({},r):void 0}},{key:"getEdgeDisplayData",value:function(e){var r=this.internals.edgeDataCache[e];return r?Object.assign({},r):void 0}},{key:"getNodeState",value:function(e){return this.stateManager.getNodeState(e)}},{key:"getEdgeState",value:function(e){return this.stateManager.getEdgeState(e)}},{key:"getGraphState",value:function(){return this.stateManager.getGraphState()}},{key:"setNodeState",value:function(e,r){return this.stateManager.setNodeState(e,r),this}},{key:"setEdgeState",value:function(e,r){return this.stateManager.setEdgeState(e,r),this}},{key:"setGraphState",value:function(e){return this.stateManager.setGraphState(e),this}},{key:"_setPanning",value:function(e){this.stateManager.setGraphState({isPanning:e})}},{key:"_setZooming",value:function(e){this.stateManager.setGraphState({isZooming:e})}},{key:"_hasNodeDrag",value:function(){var e=this.internals.dragManager;return!!(e.pendingNode||e.session)}},{key:"_showGestureHint",value:function(e){var r=this.internals.settings;r.gestureTarget==="shared"&&(this.gestureHint=this.gestureHint||new Fu(this.container),this.gestureHint.show(e,r))}},{key:"setNodesState",value:function(e,r){return this.stateManager.setNodesState(e,r),this}},{key:"setEdgesState",value:function(e,r){return this.stateManager.setEdgesState(e,r),this}},{key:"updateContainerCursor",value:function(){var e=this.stateManager.hovered,r=this.resolvedStageStyle.cursor||"";this.container.style.cursor=e&&mu(this.internals,e)||r}},{key:"refreshStageStyle",value:function(){this.resolvedStageStyle=za(this.stylesDeclaration.stage,this.stateManager.graphState),this.resolvedStageStyle.background!==void 0&&(this.container.style.backgroundColor=this.resolvedStageStyle.background),this.updateContainerCursor()}},{key:"getNodeDisplayedLabels",value:function(){return new Set(this.labelRenderer.displayedNodeLabels)}},{key:"getEdgeDisplayedLabels",value:function(){return new Set(this.labelRenderer.displayedEdgeLabels)}},{key:"getSettings",value:function(){return O({},this.internals.settings)}},{key:"getSetting",value:function(e){return this.internals.settings[e]}},{key:"getStyles",value:function(){return O({},this.stylesDeclaration)}},{key:"getPrimitives",value:function(){return O({},this.internals.primitives)}},{key:"setSetting",value:function(e,r){return this.internals.settings[e]=r,Ln(this.internals.settings),this.handleSettingsUpdate(),this.scheduleRefresh(),this}},{key:"updateSetting",value:function(e,r){return this.setSetting(e,r(this.internals.settings[e])),this}},{key:"setSettings",value:function(e){return this.internals.settings=O(O({},this.internals.settings),e),Ln(this.internals.settings),this.handleSettingsUpdate(),this.scheduleRefresh(),this}},{key:"resize",value:function(e){var r=this.width,i=this.height;if(this.width=this.container.offsetWidth,this.height=this.container.offsetHeight,this.internals.pixelRatio=$e(),this.width===0)if(this.internals.settings.allowInvalidContainer)this.width=1;else throw new Error("Sigma: Container has no width. You can set the allowInvalidContainer setting to true to stop seeing this error.");if(this.height===0)if(this.internals.settings.allowInvalidContainer)this.height=1;else throw new Error("Sigma: Container has no height. You can set the allowInvalidContainer setting to true to stop seeing this error.");if(!e&&r===this.width&&i===this.height)return this;this.labelRenderer.labelsDirty=!0;for(var o=0,s=[this.mouseLayer].concat(H(Object.values(this.extraElements)));o<s.length;o++){var l=s[o];l.style.width=this.width+"px",l.style.height=this.height+"px"}return this.webGLContext&&(this.stageCanvas.setAttribute("width",this.width*this.internals.pixelRatio+"px"),this.stageCanvas.setAttribute("height",this.height*this.internals.pixelRatio+"px"),this.webGLContext.viewport(0,0,this.width*this.internals.pixelRatio,this.height*this.internals.pixelRatio)),this.emit("resize"),this}},{key:"clear",value:function(){return this.emit("beforeClear"),this.webGLContext.bindFramebuffer(WebGLRenderingContext.FRAMEBUFFER,null),this.webGLContext.clear(WebGLRenderingContext.COLOR_BUFFER_BIT),this.emit("afterClear"),this}},{key:"scheduleStateRefresh",value:function(){this.needToRefreshState=!0,this.scheduleRender()}},{key:"refreshState",value:function(){var e=this,r;this.stateManager.flushGraphStateFlags();var i=this.stateManager.graphStateChanged&&this.internals.nodeStyleAnalysis.dependency==="graph-state",o=this.stateManager.graphStateChanged&&this.edgeStyleAnalysis.dependency==="graph-state",s=!1;if(i)this.internals.graph.forEachNode(function(f){e.refreshNodeState(f)&&(s=!0)});else if(this.internals.nodeStyleAnalysis.dependency!=="static"){var l=G(this.stateManager.dirtyNodes),u;try{for(l.s();!(u=l.n()).done;){var d=u.value;this.refreshNodeState(d)&&(s=!0)}}catch(f){l.e(f)}finally{l.f()}}if(o)this.internals.graph.forEachEdge(function(f){e.refreshEdgeState(f)&&(s=!0)});else if(this.edgeStyleAnalysis.dependency!=="static"){var c=G(this.stateManager.dirtyEdges),p;try{for(c.s();!(p=c.n()).done;){var v=p.value;this.refreshEdgeState(v)&&(s=!0)}}catch(f){c.e(f)}finally{c.f()}}this.stateManager.graphStateChanged&&(r=this.stylesDeclaration)!==null&&r!==void 0&&r.stage&&this.refreshStageStyle(),this.stateManager.clearDirtyTracking(),s&&(this.pendingProcess="full")}},{key:"refreshNodeState",value:function(e){var r=this.internals.nodeDataCache[e];if(!r||this.nodeReducer){var i,o,s,l,u=(i=this.internals.nodeDataCache[e])===null||i===void 0?void 0:i.depth,d=(o=this.internals.nodeDataCache[e])===null||o===void 0?void 0:o.zIndex,c=(s=this.internals.nodeDataCache[e])===null||s===void 0?void 0:s.labelAttachment;this.updateNode(e);var p=this.internals.nodeDataCache[e];this.internals.attachmentManager&&p.labelAttachment!==c&&this.internals.attachmentManager.invalidateNode(e);var v;this.internals.nodeShapeMap&&this.internals.nodeGlobalShapeIds&&p.shape&&p.shape in this.internals.nodeShapeMap?v=this.internals.nodeGlobalShapeIds[this.internals.nodeShapeMap[p.shape]]:v=Qe(p.shape||"circle"),(l=this.internals.nodeDataTexture).updateNode.apply(l,[e,p.x,p.y,p.size,v].concat(H(mt(p)),[p.color])),u&&p.depth!==u&&this.updateNodeDepthRanges(e,u,p.depth);var f=this.nodeProgramIndex[e];return f!==void 0&&(this.addNodeToProgram(e,f),this.nodeProgram.invalidateBuffers()),d!==void 0&&p.zIndex!==d}var b=this.internals.graph.getNodeAttributes(e),g=this.stateManager.getNodeState(e),h=r.size,m=r.shape,x=r.depth,y=r.zIndex,_=r.labelAttachment,T=r.rotationAlignment,R=r.labelRotationAlignment,E=r.color;Ia(this.stylesDeclaration.nodes,b,g,this.stateManager.graphState,this.internals.graph,r),this.postEvaluateNode(r,b,g);var D=this.nodeGraphCoords[e],P=r.x!==D.x||r.y!==D.y;if(P&&(D.x=r.x,D.y=r.y),this.normalizationFunction.applyTo(r),this.internals.nodeShapeMap?(!r.shape||!(r.shape in this.internals.nodeShapeMap))&&(r.shape=Object.keys(this.internals.nodeShapeMap)[0]):this.nodeShapeSlug&&(r.shape=this.nodeShapeSlug),this.internals.attachmentManager&&r.labelAttachment!==_&&this.internals.attachmentManager.invalidateNode(e),Ae(this.internals.nodesWithForcedLabels,e,ye(r)),Ae(this.internals.nodesWithBackdrop,e,Ot(r)),P||r.size!==h||r.shape!==m||r.rotationAlignment!==T||r.labelRotationAlignment!==R||r.color!==E){var w,A;this.internals.nodeShapeMap&&this.internals.nodeGlobalShapeIds&&r.shape&&r.shape in this.internals.nodeShapeMap?A=this.internals.nodeGlobalShapeIds[this.internals.nodeShapeMap[r.shape]]:A=Qe(r.shape||"circle"),(w=this.internals.nodeDataTexture).updateNode.apply(w,[e,r.x,r.y,r.size,A].concat(H(mt(r)),[r.color]))}this.itemBuckets.nodes.set(e,r.depth),r.depth!==x&&this.updateNodeDepthRanges(e,x,r.depth);var F=this.nodeProgramIndex[e];return F!==void 0&&(this.addNodeToProgram(e,F),this.nodeProgram.invalidateBuffers()),r.zIndex!==y}},{key:"refreshEdgeState",value:function(e){var r=this.internals.edgeDataCache[e];if(!r||this.edgeReducer){var i=r?.depth,o=r?.zIndex;this.updateEdge(e);var s=this.internals.edgeDataCache[e];i&&s.depth!==i&&this.updateEdgeDepthRanges(e,i,s.depth);var l=this.edgeProgramIndex[e];return l!==void 0&&(this.addEdgeToProgram(e,l),this.edgeProgram.invalidateBuffers()),o!==void 0&&s.zIndex!==o}var u=this.internals.graph.getEdgeAttributes(e),d=this.stateManager.getEdgeState(e),c=r.depth,p=r.zIndex,v=r.size,f=r.path,b=r.selfLoopPath,g=r.parallelPath,h=r.head,m=r.tail;ka(this.stylesDeclaration.edges,u,d,this.stateManager.graphState,this.internals.graph,r),this.postEvaluateEdge(r,u),this.applyEdgeSpread(e,r,d),Ae(this.internals.edgesWithForcedLabels,e,ye(r)),this.itemBuckets.edges.set(e,r.depth),r.depth!==c&&this.updateEdgeDepthRanges(e,c,r.depth);var x=this.edgeProgramIndex[e];if(x!==void 0){var y=r.size!==v||r.path!==f||r.selfLoopPath!==b||r.parallelPath!==g||r.head!==h||r.tail!==m;if(y)this.addEdgeToProgram(e,x),this.edgeProgram.invalidateBuffers();else{var _=this.internals.graph.source(e),T=this.internals.graph.target(e),R=this.internals.nodeDataCache[_],E=this.internals.nodeDataCache[T],D=this.edgeTextureIndexCache[e];this.edgeProgram.process(nt(this.pickingState,"edge",e),x,R,E,r,D),this.edgeProgram.invalidateBuffers()}}return r.zIndex!==p}},{key:"refresh",value:function(e){var r=this,i=e?.skipIndexation!==void 0?e?.skipIndexation:!1,o=e?.schedule!==void 0?e.schedule:!1,s=!e||!e.partialGraph;if(s)this.clearEdgeIndices(),this.clearNodeIndices(),this.internals.graph.forEachNode(function(R){return r.addNode(R)}),this.edgeGroups.rebuild(),this.internals.graph.forEachEdge(function(R){return r.addEdge(R)}),this.pendingProcess="full";else{for(var l,u,d=((l=e.partialGraph)===null||l===void 0?void 0:l.nodes)||[],c=0,p=d?.length||0;c<p;c++){var v,f,b=""+d[c],g=(v=this.internals.nodeDataCache[b])===null||v===void 0?void 0:v.labelAttachment;if(this.updateNode(b),this.internals.attachmentManager&&((f=this.internals.nodeDataCache[b])!==null&&f!==void 0&&f.labelAttachment||g)&&this.internals.attachmentManager.invalidateNode(b),i){var h=this.nodeProgramIndex[b];if(h===void 0)throw new Error('Sigma: node "'.concat(b,`" can't be repaint`));this.addNodeToProgram(b,h)}}i&&d.length>0&&(this.nodeProgram.invalidateBuffers(),this.labelRenderer.labelsDirty=!0);for(var m=(e==null||(u=e.partialGraph)===null||u===void 0?void 0:u.edges)||[],x=0,y=m.length;x<y;x++){var _=""+m[x];if(this.updateEdge(_),i){var T=this.edgeProgramIndex[_];if(T===void 0)throw new Error('Sigma: edge "'.concat(_,`" can't be repaint`));this.addEdgeToProgram(_,T)}}i&&m.length>0&&(this.edgeProgram.invalidateBuffers(),this.labelRenderer.labelsDirty=!0),!i&&this.pendingProcess!=="full"&&(this.pendingProcess=m.length>0?"full":"nodes")}return o?this.scheduleRender():this.render(),this}},{key:"scheduleRender",value:function(){var e=this;return this.renderFrame||(this.renderFrame=requestAnimationFrame(function(){e.render()})),this}},{key:"scheduleRefresh",value:function(e){return this.refresh(O(O({},e),{},{schedule:!0}))}},{key:"getViewportZoomedState",value:function(e,r){var i=this.camera.getState(),o=i.ratio,s=i.angle,l=i.x,u=i.y,d=this.internals.settings,c=d.minCameraRatio,p=d.maxCameraRatio;typeof p=="number"&&(r=Math.min(r,p)),typeof c=="number"&&(r=Math.max(r,c));var v=r/o,f={x:this.width/2,y:this.height/2},b=this.viewportToFramedGraph(e),g=this.viewportToFramedGraph(f);return{angle:s,x:(b.x-g.x)*(1-v)+l,y:(b.y-g.y)*(1-v)+u,ratio:r}}},{key:"viewRectangle",value:function(){var e=this.viewportToFramedGraph({x:0,y:0}),r=this.viewportToFramedGraph({x:this.width,y:0}),i=this.viewportToFramedGraph({x:0,y:this.height});return{x1:e.x,y1:e.y,x2:r.x,y2:r.y,height:r.y-i.y}}},{key:"framedGraphToViewport",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},i=!!r.cameraState||!!r.viewportDimensions||!!r.graphDimensions||!!r.padding,o=r.matrix||(i?be(r.cameraState||this.camera.getState(),r.viewportDimensions||this.getDimensions(),r.graphDimensions||this.getGraphDimensions(),r.padding||this.getStagePadding()):this.matrix),s=we(o,e);return{x:(1+s.x)*this.width/2,y:(1-s.y)*this.height/2}}},{key:"viewportToFramedGraph",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},i=!!r.cameraState||!!r.viewportDimensions||!!r.graphDimensions||!!r.padding,o=r.matrix||(i?be(r.cameraState||this.camera.getState(),r.viewportDimensions||this.getDimensions(),r.graphDimensions||this.getGraphDimensions(),r.padding||this.getStagePadding(),!0):this.invMatrix),s=we(o,{x:e.x/this.width*2-1,y:1-e.y/this.height*2});return isNaN(s.x)&&(s.x=0),isNaN(s.y)&&(s.y=0),s}},{key:"viewportToGraph",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{};return this.normalizationFunction.inverse(this.viewportToFramedGraph(e,r))}},{key:"graphToViewport",value:function(e){var r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{};return this.framedGraphToViewport(this.normalizationFunction(e),r)}},{key:"graphToFramedGraph",value:function(e){return this.normalizationFunction(e)}},{key:"framedGraphToGraph",value:function(e){return this.normalizationFunction.inverse(e)}},{key:"getGraphToViewportRatio",value:function(){var e={x:0,y:0},r={x:1,y:1},i=Math.sqrt(Math.pow(e.x-r.x,2)+Math.pow(e.y-r.y,2)),o=this.graphToViewport(e),s=this.graphToViewport(r),l=Math.sqrt(Math.pow(o.x-s.x,2)+Math.pow(o.y-s.y,2));return l/i}},{key:"computeNodeExtent",value:function(){var e=this.nodeGraphCoords,r=Object.keys(e);if(!r.length)return{x:[0,1],y:[0,1]};for(var i=1/0,o=-1/0,s=1/0,l=-1/0,u=0,d=r.length;u<d;u++){var c=e[r[u]],p=c.x,v=c.y;p<i&&(i=p),p>o&&(o=p),v<s&&(s=v),v>l&&(l=v)}return{x:[i,o],y:[s,l]}}},{key:"getBBox",value:function(){return this.nodeExtent}},{key:"getCustomBBox",value:function(){return this.customBBox}},{key:"setCustomBBox",value:function(e){return this.customBBox=e,this.scheduleRender(),this}},{key:"kill",value:function(){var e,r,i;this.emit("kill"),this.removeAllListeners(),this.camera.cancelAnimation(),this.unbindCameraHandlers(),window.removeEventListener("resize",this.activeListeners.handleResize),this.mouseCaptor.kill(),this.touchCaptor.kill(),this.internals.hoverResolver.kill(),this.unbindGraphHandlers(),this.clearIndices(),this.clearState(),this.internals.nodeDataCache={},this.internals.edgeDataCache={},this.renderFrame&&(cancelAnimationFrame(this.renderFrame),this.renderFrame=null);for(var o=this.container;o.firstChild;)o.removeChild(o.firstChild);this.nodeProgram.kill(),this.nodeFramePass.kill(),this.edgeProgram.kill(),this.edgeFramePass.kill(),this.internals.labelProgram.kill(),this.internals.edgeLabelProgram.kill(),this.internals.edgeLabelBackgroundProgram.kill(),this.internals.backdropProgram.kill(),this.internals.labelBackgroundProgram.kill(),(e=this.internals.attachmentProgram)===null||e===void 0||e.kill(),(r=this.internals.attachmentManager)===null||r===void 0||r.kill(),this.internals.attachmentProgram=null,this.internals.attachmentManager=null;var s=G(this.customLayerPrograms.values()),l;try{for(s.s();!(l=s.n()).done;){var u=l.value.program;u.kill()}}catch(p){s.e(p)}finally{s.f()}if(this.customLayerPrograms.clear(),this.sdfAtlas&&(this.sdfAtlas=null),this.internals.nodeDataTexture&&(this.internals.nodeDataTexture.kill(),this.internals.nodeDataTexture=null),this.internals.nodeFrameTexture&&(this.internals.nodeFrameTexture.kill(),this.internals.nodeFrameTexture=null),this.internals.edgeDataTexture&&(this.internals.edgeDataTexture.kill(),this.internals.edgeDataTexture=null),this.internals.edgeFrameTexture&&(this.internals.edgeFrameTexture.kill(),this.internals.edgeFrameTexture=null),this.webGLContext){var d;(d=this.webGLContext.getExtension("WEBGL_lose_context"))===null||d===void 0||d.loseContext(),this.webGLContext=null}(i=this.gestureHint)===null||i===void 0||i.kill(),this.gestureHint=null,this.mouseLayer.remove();for(var c in this.extraElements)this.extraElements[c].remove();this.extraElements={}}},{key:"scaleSize",value:function(){var e=arguments.length>0&&arguments[0]!==void 0?arguments[0]:1,r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:this.camera.ratio;return e/this.internals.settings.zoomToSizeRatioFunction(r)*(this.getSetting("itemSizesReference")==="positions"?r*this.graphToViewportRatio:1)}},{key:"getStageCanvas",value:function(){return this.stageCanvas}},{key:"getMouseLayer",value:function(){return this.mouseLayer}}])})(Sn),Ve=So,Ou=Nt,Bu=kt,Wu=zt,Uu=ft;var Rr={};ha(Rr,{AttachmentManager:()=>Qn,DEFAULT_LABEL_BACKGROUND_PADDING:()=>$t,DEFAULT_LABEL_MARGIN:()=>Be,DataTexture:()=>_t,DepthBucketCollection:()=>tn,EdgeDataTexture:()=>ea,EdgeFramePass:()=>hr,FrameTexture:()=>nn,GLSL_GET_LABEL_DIRECTION:()=>Bn,GLSL_LABEL_BOX_CENTER:()=>Wn,GLSL_NODE_SIZE_TO_PIXELS:()=>On,GLSL_READ_FRAME_TEXEL:()=>Ue,GLSL_READ_NODE_COLOR:()=>ja,GLSL_READ_NODE_DATA:()=>me,GLSL_READ_NODE_FLAGS:()=>Le,GLSL_ROTATE_2D:()=>We,GLSL_SDF_BOX:()=>Ua,GLSL_SDF_ROTATED_BOX:()=>Ha,GLSL_SDF_ROUNDED_BOX:()=>Va,GLSL_SDF_ROUNDED_ROTATED_BOX:()=>Xa,GLStateGuard:()=>ud,LabelProgram:()=>jn,NODE_DATA_TEXELS_PER_NODE:()=>Qt,NodeDataTexture:()=>Jn,NodeLabelFramePass:()=>qn,POSITION_MODE_MAP:()=>Oe,Program:()=>Pe,clearShapeInstanceRegistry:()=>Mi,collectAttributes:()=>Qa,collectBackdropUniforms:()=>tr,collectLabelUniforms:()=>or,collectUniforms:()=>$a,createBackdropProgram:()=>ar,createEdgeLabelBackgroundProgram:()=>fr,createEdgeLabelProgram:()=>vr,createEdgeProgram:()=>Kn,createLabelProgram:()=>lr,createNodeProgram:()=>Yn,dedupeShapeUniforms:()=>Je,extremityArrow:()=>rd,extremityBar:()=>id,extremityCircle:()=>od,extremityDiamond:()=>sd,extremitySquare:()=>ld,generateBackdropFragmentShader:()=>er,generateBackdropShaders:()=>nr,generateBackdropVertexShader:()=>Ja,generateEdgeLabelShaders:()=>gr,generateEdgeShaders:()=>Mn,generateFindEdgeDistanceForShapes:()=>qa,generateFragmentShader:()=>Za,generateLabelFragmentShader:()=>ir,generateLabelShaders:()=>sr,generateLabelVertexShader:()=>rr,generateNodeShapeSelectorGLSL:()=>Wa,generateSDFCall:()=>yt,generateShaders:()=>Nn,generateShapeSelectorGLSL:()=>Ba,generateVertexShader:()=>Ka,getAllShapeGLSL:()=>Oa,getAttributesItemsCount:()=>Vt,getRegisteredShapeInstance:()=>wi,getRegisteredShapeSlugs:()=>ki,getShapeFromSlug:()=>Ii,getShapeGLSL:()=>zi,getShapeGLSLForShapes:()=>Zt,getShapeId:()=>Qe,getStaticAttributeDefault:()=>Gn,isAttributeSource:()=>oe,killProgram:()=>zn,layerDashed:()=>$u,layerFill:()=>dt,layerGradient:()=>Ju,layerPlain:()=>Ee,loadFragmentShader:()=>Yt,loadProgram:()=>Kt,loadVertexShader:()=>qt,numberToGLSLFloat:()=>Y,pathCurved:()=>ed,pathCurvedS:()=>td,pathLine:()=>pn,pathLoop:()=>bn,pathStep:()=>nd,pathStepCurved:()=>ad,registerShapeInstance:()=>Ga,resolveEdgeColorValue:()=>Ke,sdfCircle:()=>Ye,sdfDiamond:()=>Xu,sdfRectangle:()=>ju,sdfSquare:()=>Hu,sdfTriangle:()=>Vu});var Gc=Se(Ze());function Eo(n,a){return typeof n=="number"?n:(q(n)==="object"&&n!==null&&"attribute"in n,a)}function Hu(n){var a=n??{},t=a.cornerRadius,e=a.rotation,r=Eo(t,0),i=Eo(e,0),o=`
`.concat(We,`
float sdf_square(vec2 uv, float size, float cornerRadius, float rotation) {
  // Apply rotation if needed
  vec2 p = uv;
  if (rotation != 0.0) {
    p = rotate2D(rotation) * p;
  }

  // Distance to box with given corner radius
  // Based on Inigo Quilez's box SDF: https://iquilezles.org/articles/distfunctions2d/
  vec2 d = abs(p) - vec2(size - cornerRadius);
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0) - cornerRadius;
}
`);return{name:"square",glsl:o,uniforms:[{name:"u_cornerRadius",type:"float",value:r},{name:"u_rotation",type:"float",value:i}],inradiusFactor:Math.SQRT1_2}}function Ro(n,a){return typeof n=="number"?n:(q(n)==="object"&&n!==null&&"attribute"in n,a)}function Vu(n){var a=n??{},t=a.cornerRadius,e=a.rotation,r=Ro(t,0),i=Ro(e,0),o=`
`.concat(We,`
float sdf_triangle(vec2 uv, float size, float cornerRadius, float rotation) {
  // Apply rotation if needed
  vec2 p = uv;
  if (rotation != 0.0) {
    p = rotate2D(rotation) * p;
  }

  // Equilateral triangle SDF
  // Based on Inigo Quilez's triangle SDF: https://iquilezles.org/articles/distfunctions2d/
  //
  // The IQ formula uses parameter 'r' where the triangle has width = 2r.
  // For circumradius R (distance from centroid to vertex):
  //   R = r * 2 / sqrt(3), so r = R * sqrt(3) / 2
  const float k = sqrt(3.0);
  float r = size * k / 2.0;

  p.x = abs(p.x) - r;
  p.y = p.y + r / k;
  if (p.x + k * p.y > 0.0) {
    p = vec2(p.x - k * p.y, -k * p.x - p.y) / 2.0;
  }
  p.x -= clamp(p.x, -2.0 * r, 0.0);
  float dist = -length(p) * sign(p.y);

  // Apply corner radius if specified
  if (cornerRadius > 0.0) {
    dist = dist + cornerRadius;
  }

  return dist;
}
`);return{name:"triangle",glsl:o,uniforms:[{name:"u_cornerRadius",type:"float",value:r},{name:"u_rotation",type:"float",value:i}],inradiusFactor:.5}}function Ao(n,a){return typeof n=="number"?n:(q(n)==="object"&&n!==null&&"attribute"in n,a)}function Xu(n){var a=n??{},t=a.cornerRadius,e=a.rotation,r=Ao(t,0),i=Ao(e,0),o=`
`.concat(We,`
float sdf_diamond(vec2 uv, float size, float cornerRadius, float rotation) {
  // Apply rotation if needed
  vec2 p = uv;
  if (rotation != 0.0) {
    p = rotate2D(rotation) * p;
  }

  // Diamond SDF - using rhombus formula from Inigo Quilez
  // https://iquilezles.org/articles/distfunctions2d/
  // For a diamond (square rotated 45\xB0), b = (size, size)
  vec2 b = vec2(size, -size);
  p = abs(p);
  float h = clamp((dot(b, p) + b.y * b.y) / dot(b, b), 0.0, 1.0);
  p -= b * vec2(h, h - 1.0);
  float d = length(p) * sign(p.x);

  // Apply corner radius if specified
  if (cornerRadius > 0.0) {
    d = d + cornerRadius;
  }

  return d;
}
`);return{name:"diamond",glsl:o,uniforms:[{name:"u_cornerRadius",type:"float",value:r},{name:"u_rotation",type:"float",value:i}],inradiusFactor:Math.SQRT1_2}}function ju(n){var a=n??{},t=a.aspectRatio,e=t===void 0?{attribute:"aspectRatio"}:t,r=a.cornerRadius,i=a.rotation,o=`
`.concat(We,`
float sdf_rectangle(vec2 uv, float size, float cornerRadius, float rotation, float aspectRatio) {
  // Apply rotation if needed
  vec2 p = uv;
  if (rotation != 0.0) {
    p = rotate2D(rotation) * p;
  }

  vec2 halfExtent = aspectRatio >= 1.0 ? vec2(size, size / aspectRatio) : vec2(size * aspectRatio, size);
  // Keeps thin rectangles from growing past their half extent
  float radius = min(cornerRadius, min(halfExtent.x, halfExtent.y));

  // Based on Inigo Quilez's box SDF: https://iquilezles.org/articles/distfunctions2d/
  vec2 d = abs(p) - (halfExtent - radius);
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0) - radius;
}
`),s=[{name:"u_cornerRadius",type:"float",value:typeof r=="number"?r:0},{name:"u_rotation",type:"float",value:typeof i=="number"?i:0}],l=function(v){return"0.70710678 / max(".concat(v,", 1.0 / ").concat(v,")")};if(!oe(e))return{name:"rectangle",glsl:o,uniforms:[].concat(s,[{name:"u_aspectRatio",type:"float",value:e}]),inradiusFactor:Math.SQRT1_2,inradiusFactorGLSL:l(Y(e))};var u=e.attribute,d=e.default,c=d===void 0?1:d;return{name:"rectangle",glsl:o,uniforms:s,attributes:[{name:"aspectRatio",size:1,type:WebGL2RenderingContext.FLOAT,source:u}],variables:S({},u,{type:"number",default:c}),inradiusFactor:Math.SQRT1_2,inradiusFactorGLSL:l("v_aspectRatio")}}var qu="pixels",Yu="butt";function Ku(n){return n===void 0||n===!1?{tail:!1,head:!1}:n===!0?{tail:!0,head:!0}:n==="head"?{tail:!1,head:!0}:{tail:!0,head:!1}}function Zu(n){var a,t;return n===void 0?{tail:0,head:0}:typeof n=="number"?{tail:n,head:n}:{tail:(a=n.tail)!==null&&a!==void 0?a:0,head:(t=n.head)!==null&&t!==void 0?t:0}}function $u(n){var a,t,e,r,i,o,s,l=n??{},u=(a=l.dashColor)!==null&&a!==void 0?a:{attribute:"color"},d=(t=l.gapColor)!==null&&t!==void 0?t:0,c={dashSize:(e=l.dashSize)!==null&&e!==void 0?e:{value:10,mode:"pixels"},gapSize:(r=l.gapSize)!==null&&r!==void 0?r:{value:10,mode:"pixels"},dashOffset:(i=l.dashOffset)!==null&&i!==void 0?i:{value:0,mode:"pixels"}},p=(o=l.align)!==null&&o!==void 0?o:.5,v=(s=l.cap)!==null&&s!==void 0?s:Yu,f=Ku(l.solidExtremities),b=Zu(l.solidMargin),g=Ke(u,"dashColor"),h=[c.dashSize,c.gapSize,c.dashOffset].map(function(A){var F;return((F=A.mode)!==null&&F!==void 0?F:qu)==="relative"?1:0}),m=[{name:"u_sizeMode",type:"vec3",value:h},{name:"u_align",type:"float",value:p},{name:"u_solidExtremities",type:"vec2",value:[f.tail?1:0,f.head?1:0]},{name:"u_solidMargin",type:"vec2",value:[b.tail,b.head]}],x=H(g.attributes),y=g.needsNodeColors,_;if(typeof d=="number")_="vec4(dashColor.rgb, dashColor.a * ".concat(Y(d),")");else{var T=Ke(d,"gapColor");_=T.glsl,x.push.apply(x,H(T.attributes)),y=y||T.needsNodeColors}var R=!("value"in c.dashSize),E=!("value"in c.gapSize),D=!("value"in c.dashOffset);["dashSize","gapSize","dashOffset"].forEach(function(A){if("value"in c[A])m.push({name:"u_".concat(A),type:"float",value:c[A].value});else{var F;x.push({name:"a_".concat(A),size:1,type:WebGL2RenderingContext.FLOAT,source:c[A].attribute}),m.push({name:"u_".concat(A),type:"float",value:(F=c[A].default)!==null&&F!==void 0?F:0})}});var P=function(F,L){return L?"(v_".concat(F," > 0.0 ? v_").concat(F," : u_").concat(F,")"):"u_".concat(F)},w=`
// Dashed pattern layer with antialiased boundaries
// Uniforms:
//   u_dashSize: size of each dash (or default when using attribute)
//   u_gapSize: size of gaps between dashes (or default when using attribute)
//   u_dashOffset: offset to shift the pattern (or default when using attribute)
//   u_sizeMode: vec3 indicating if values are thickness-relative (x=dash, y=gap, z=offset)
//   u_align: pattern alignment (0=start, 0.5=center, 1=end)
//   u_solidExtremities: vec2(tail, head) - 1.0 means solid, 0.0 means dashed
//   u_solidMargin: vec2(tail, head) - extra solid margin in pixels
`.concat(R?"// Varying: v_dashSize for per-edge dash size":"",`
`).concat(E?"// Varying: v_gapSize for per-edge gap size":"",`
`).concat(D?"// Varying: v_dashOffset for per-edge dash offset":"",`

vec4 layer_dashed(EdgeContext ctx) {
  // Dash color (straight alpha, matching v_color and blendOver)
  vec4 dashColor = `).concat(g.glsl,`;

  // Check for solid zones first (extremities and margins)
  // v_zone: 0=tail extremity, 1=body, 2=head extremity
  // v_tailLengthRatio and v_headLengthRatio give extremity lengths as ratio of thickness

  // Tail solid zone check
  if (u_solidExtremities.x > 0.5 && v_zone < 0.5) {
    // In tail extremity zone and solidExtremities.tail is enabled
    return dashColor;
  }
  // Head solid zone check
  if (u_solidExtremities.y > 0.5 && v_zone > 1.5) {
    // In head extremity zone and solidExtremities.head is enabled
    return dashColor;
  }

  // Compute extremity lengths in world units for margin calculation
  float tailExtremityLength = v_tailLengthRatio * ctx.thickness;
  float headExtremityLength = v_headLengthRatio * ctx.thickness;

  // Convert pixel margins to world units (same formula as thickness conversion)
  float tailMarginWorld = u_solidMargin.x * u_correctionRatio / u_sizeRatio;
  float headMarginWorld = u_solidMargin.y * u_correctionRatio / u_sizeRatio;

  // Tail margin check (margin starts after extremity zone)
  float tailSolidZone = (u_solidExtremities.x > 0.5 ? tailExtremityLength : 0.0) + tailMarginWorld;
  if (ctx.distanceFromSource < tailSolidZone) {
    return dashColor;
  }

  // Head margin check (margin starts before extremity zone)
  float headSolidZone = (u_solidExtremities.y > 0.5 ? headExtremityLength : 0.0) + headMarginWorld;
  if (ctx.distanceToTarget < headSolidZone) {
    return dashColor;
  }

  // Get dash size values (from attribute if available, otherwise uniform)
  float dashSizeValue = `).concat(P("dashSize",R),`;
  float gapSizeValue = `).concat(P("gapSize",E),`;
  float dashOffsetValue = `).concat(P("dashOffset",D),`;

  // Compute actual sizes (either in pixels converted to world units, or relative to thickness)
  float pixelToWorld = u_correctionRatio / u_sizeRatio;
  float dashSize = dashSizeValue * (u_sizeMode.x > 0.5 ? ctx.thickness : pixelToWorld);
  float gapSize = gapSizeValue * (u_sizeMode.y > 0.5 ? ctx.thickness : pixelToWorld);
  float dashOffset = dashOffsetValue * (u_sizeMode.z > 0.5 ? ctx.thickness : pixelToWorld);

  // Early return when no visible dash pattern:
  // - dashSize \u2248 0: no dashes to show, return transparent (let plain layer show through)
  // - gapSize \u2248 0: all dash/no gap, effectively solid, return transparent (let plain layer handle it)
  // Threshold scales with pixelToWorld so it stays ~0.1px regardless of zoom
  float dashThreshold = 0.1 * pixelToWorld;
  if (dashSize < dashThreshold || gapSize < dashThreshold) {
    return vec4(0.0);
  }

  // Pattern length is dash + gap
  float patternLength = dashSize + gapSize;

  // Adjust distances for solid zones (pattern starts after solid zones)
  float adjustedDistFromSource = ctx.distanceFromSource - tailSolidZone;
  float adjustedDistToTarget = ctx.distanceToTarget - headSolidZone;

  // Compute alignment anchor point
  // - align: 0 \u2192 anchor at start, pattern begins with a dash
  // - align: 1 \u2192 anchor at end, pattern ends with a dash
  // - align: 0.5 \u2192 anchor at center, pattern is symmetric
  float dashedLength = adjustedDistFromSource + adjustedDistToTarget;
  float anchorDist = u_align * dashedLength;

  // Position within the repeating pattern
  // By subtracting anchorDist, we ensure the anchor point maps to position 0 in the pattern
  // This avoids the unstable mod(dashedLength, patternLength) operation
  float posInPattern = mod(adjustedDistFromSource - anchorDist + dashOffset, patternLength);

  // Signed longitudinal distance to the nearest dash center, wrapping across
  // pattern repetitions so both dash edges antialias correctly
  float longFromCenter =
    mod(posInPattern - dashSize * 0.5 + patternLength * 0.5, patternLength) - patternLength * 0.5;

  // Compute signed distance field for the dash
  // Positive inside dash, negative inside gap
`).concat(v==="round"?`  // Capsule SDF: round caps carved inside the dash length, so a dash never
  // exceeds dashSize. Dashes shorter than the thickness degenerate to circles
  // (dots) of diameter dashSize.
  // ctx.sdf is 0 at the stroke boundary, so shift it back to centerline distance
  float transverse = ctx.sdf + ctx.thickness * 0.5;
  float capRadius = min(ctx.thickness, dashSize) * 0.5;
  float halfLength = dashSize * 0.5 - capRadius;
  vec2 q = vec2(max(abs(longFromCenter) - halfLength, 0.0), transverse);
  float sdf = capRadius - length(q);`:"  float sdf = dashSize * 0.5 - abs(longFromCenter);",`

  // Apply antialiasing using smoothstep
  // aaWidth is in world units, same as our distance
  float dashAlpha = smoothstep(-ctx.aaWidth, ctx.aaWidth, sdf);

  // Gap color (straight alpha, like the dash color)
  vec4 gapColor = `).concat(_,`;

  // Blend between gap and dash colors
  return mix(gapColor, dashColor, dashAlpha);
}
`);return{name:"dashed",glsl:w,uniforms:m,attributes:x,needsNodeColors:y}}function Qu(n){var a=n.map(function(d){return d.offset});a[0]===void 0&&(a[0]=0),a[n.length-1]===void 0&&(a[n.length-1]=1);for(var t=0,e=0;e<a.length;e++){var r=a[e];r!==void 0&&(t=Math.max(t,Math.min(Math.max(r,0),1)),a[e]=t)}for(var i=1;i<a.length;i++)if(a[i]===void 0){for(var o=i+1;a[o]===void 0;)o++;for(var s=a[i-1],l=a[o],u=i;u<o;u++)a[u]=s+(l-s)*(u-i+1)/(o-i+1);i=o}return a}function Ju(n){if(n.stops.length<2)throw new Error("layerGradient: at least two stops are required");var a=n.stops.map(function(u){return typeof u=="string"?{color:u,offset:void 0}:{color:"color"in u?u.color:u,offset:u.offset}}),t=Qu(a),e=a.map(function(u,d){return Ke(u.color,"gradientStop".concat(d))}),r=n.enabled,i=e.flatMap(function(u){return u.attributes});if(r){var o;i.push({name:"a_gradient",size:1,type:WebGL2RenderingContext.FLOAT,source:r.attribute,defaultValue:(o=r.default)!==null&&o!==void 0?o:!0})}var s=t.map(function(u,d){if(d===0)return"";var c=t[d-1].toFixed(6),p=Math.max(u-t[d-1],1e-6).toFixed(6);return`
  vec4 c`.concat(d," = ").concat(e[d].glsl,`;
  color = mix(color, vec4(c`).concat(d,".rgb * c").concat(d,".a, c").concat(d,".a), clamp((ctx.t - ").concat(c,") / ").concat(p,", 0.0, 1.0));")}).join(""),l=`
// Gradient layer: interpolates the color stops over the visible span of the
// edge (ctx.t is 0 where the edge leaves the source node, 1 where it reaches
// the target node). Interpolation happens in premultiplied space so fading to
// a (semi-)transparent stop keeps the hue instead of darkening through black;
// the returned color is straight-alpha, matching the blendOver convention.
vec4 layer_gradient(EdgeContext ctx) {`.concat(r?`
  // Per-edge toggle: fall through to the layers below when disabled
  if (v_gradient < 0.5) return vec4(0.0);
`:"",`
  vec4 c0 = `).concat(e[0].glsl,`;
  vec4 color = vec4(c0.rgb * c0.a, c0.a);`).concat(s,`
  return color.a > 0.0 ? vec4(color.rgb / color.a, color.a) : vec4(0.0);
}
`);return{name:"gradient",glsl:l,uniforms:[],attributes:i,needsNodeColors:e.some(function(u){return u.needsNodeColors})}}function ed(n){var a=n??{},t=a.segments,e=t===void 0?16:t,r=`
// Compute control point from curvature
// Control point is placed perpendicular to the midpoint of source-target line
vec2 computeControlPoint(vec2 source, vec2 target, float curvature) {
  vec2 midpoint = 0.5 * (source + target);
  vec2 delta = target - source;
  // Perpendicular direction (rotated 90 degrees)
  vec2 perp = vec2(-delta.y, delta.x);
  float len = length(perp);
  if (len < 0.0001) return midpoint;
  perp = perp / len;
  // Offset by curvature * edge length
  return midpoint + perp * curvature * len;
}

// Position at parameter t \u2208 [0, 1]
vec2 path_curved_position(float t, vec2 source, vec2 target) {
  float curvature = v_curvature;
  vec2 control = computeControlPoint(source, target, curvature);
  float u = 1.0 - t;
  return u * u * source + 2.0 * u * t * control + t * t * target;
}

// Derivative of quadratic Bezier (for efficient arc length computation)
vec2 path_curved_derivative(float t, vec2 source, vec2 target) {
  float curvature = v_curvature;
  vec2 control = computeControlPoint(source, target, curvature);
  // B'(t) = 2(1-t)(P1-P0) + 2t(P2-P1)
  return 2.0 * (1.0 - t) * (control - source) + 2.0 * t * (target - control);
}

// Approximate arc length using 5-point Gauss-Legendre quadrature
float path_curved_length(vec2 source, vec2 target) {
  // Gauss-Legendre 5-point weights and abscissae
  const float x1 = 0.9061798459, x2 = 0.5384693101;
  const float w1 = 0.2369268850, w2 = 0.4786286705, w3 = 0.5688888889;

  // Transform from [-1,1] to [0,1]: t = 0.5 * (x + 1)
  float t1a = 0.5 * (-x1 + 1.0), t1b = 0.5 * (x1 + 1.0);
  float t2a = 0.5 * (-x2 + 1.0), t2b = 0.5 * (x2 + 1.0);

  // Evaluate derivative magnitudes at sample points
  float d1a = length(path_curved_derivative(t1a, source, target));
  float d1b = length(path_curved_derivative(t1b, source, target));
  float d2a = length(path_curved_derivative(t2a, source, target));
  float d2b = length(path_curved_derivative(t2b, source, target));
  float d3 = length(path_curved_derivative(0.5, source, target));

  // Sum weighted samples (factor of 0.5 for interval transformation)
  return 0.5 * (w1 * (d1a + d1b) + w2 * (d2a + d2b) + w3 * d3);
}
`;return{name:"curved",segments:e,glsl:r,uniforms:[],attributes:[{name:"curvature",size:1,type:WebGL2RenderingContext.FLOAT}],variables:{curvature:{type:"number",default:0}},spread:{variable:"curvature",compute:function(o,s,l){return(o-(s-1)/2)*l}}}}function td(n){var a=n??{},t=a.segments,e=t===void 0?16:t,r=a.orientation,i=r===void 0?"automatic":r,o=a.rotateWithCamera,s=o===void 0?!1:o,l=a.curveOffset,u=l===void 0?.5:l,d=a.curvePosition,c=d===void 0?.5:d,p,v=0;typeof i=="number"?(p=3,v=i):i==="horizontal"?p=1:i==="vertical"?p=2:p=0;var f=`
// S-curve path constants (baked from options)
const int CURVEDS_ORIENTATION = `.concat(p,`;
const float CURVEDS_FIXED_ANGLE = `).concat(Y(v),`;
const bool CURVEDS_ROTATE_WITH_CAMERA = `).concat(s?"true":"false",`;
const float CURVEDS_OFFSET = `).concat(Y(u),`;
const float CURVEDS_POSITION = `).concat(Y(c),`;

// ============================================================================
// HELPER: Rotate a 2D vector by angle (counter-clockwise)
// ============================================================================
vec2 curvedS_rotate(vec2 v, float angle) {
  float c = cos(angle);
  float s = sin(angle);
  return vec2(c * v.x - s * v.y, s * v.x + c * v.y);
}

// ============================================================================
// HELPER: Get control point direction based on orientation
// ============================================================================
vec2 getCurvedSControlDirection(vec2 source, vec2 target) {
  vec2 delta = target - source;

  if (CURVEDS_ORIENTATION == 1) {
    // Horizontal: control points extend horizontally
    return vec2(sign(delta.x), 0.0);
  } else if (CURVEDS_ORIENTATION == 2) {
    // Vertical: control points extend vertically
    return vec2(0.0, sign(delta.y));
  } else if (CURVEDS_ORIENTATION == 3) {
    // Fixed angle
    return vec2(cos(CURVEDS_FIXED_ANGLE), sin(CURVEDS_FIXED_ANGLE));
  } else {
    // Automatic: choose based on which delta is larger
    if (abs(delta.x) >= abs(delta.y)) {
      return vec2(sign(delta.x), 0.0);
    } else {
      return vec2(0.0, sign(delta.y));
    }
  }
}

// ============================================================================
// HELPER: Get cubic B\xE9zier control points
// ============================================================================
void getCurvedSControlPoints(vec2 source, vec2 target, out vec2 c1, out vec2 c2) {
  vec2 dir = getCurvedSControlDirection(source, target);
  float dist = length(target - source);

  // Control point distances based on curveOffset
  float offset1 = dist * CURVEDS_OFFSET * CURVEDS_POSITION * 2.0;
  float offset2 = dist * CURVEDS_OFFSET * (1.0 - CURVEDS_POSITION) * 2.0;

  c1 = source + dir * offset1;
  c2 = target - dir * offset2;
}

// ============================================================================
// HELPER: Evaluate cubic B\xE9zier: B(t) = (1-t)\xB3P\u2080 + 3(1-t)\xB2tP\u2081 + 3(1-t)t\xB2P\u2082 + t\xB3P\u2083
// ============================================================================
vec2 curvedS_cubicBezier(float t, vec2 p0, vec2 p1, vec2 p2, vec2 p3) {
  float t2 = t * t;
  float t3 = t2 * t;
  float mt = 1.0 - t;
  float mt2 = mt * mt;
  float mt3 = mt2 * mt;

  return mt3 * p0 + 3.0 * mt2 * t * p1 + 3.0 * mt * t2 * p2 + t3 * p3;
}

// ============================================================================
// HELPER: Evaluate cubic B\xE9zier derivative: B'(t)
// ============================================================================
vec2 curvedS_cubicBezierDerivative(float t, vec2 p0, vec2 p1, vec2 p2, vec2 p3) {
  float t2 = t * t;
  float mt = 1.0 - t;
  float mt2 = mt * mt;

  // B'(t) = 3(1-t)\xB2(P\u2081-P\u2080) + 6(1-t)t(P\u2082-P\u2081) + 3t\xB2(P\u2083-P\u2082)
  return 3.0 * mt2 * (p1 - p0) + 6.0 * mt * t * (p2 - p1) + 3.0 * t2 * (p3 - p2);
}

// ============================================================================
// POSITION - Core function for vertex placement
// ============================================================================
vec2 path_curvedS_position(float t, vec2 source, vec2 target) {
  // Apply camera rotation if not rotating with camera
  vec2 src = source;
  vec2 tgt = target;
  if (!CURVEDS_ROTATE_WITH_CAMERA) {
    src = curvedS_rotate(source, -u_cameraAngle);
    tgt = curvedS_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Handle degenerate case (very close nodes) -> straight line
  if (length(delta) < 0.0001) {
    vec2 result = mix(src, tgt, t);
    if (!CURVEDS_ROTATE_WITH_CAMERA) {
      result = curvedS_rotate(result, u_cameraAngle);
    }
    return result;
  }

  // Get control points
  vec2 c1, c2;
  getCurvedSControlPoints(src, tgt, c1, c2);

  // Evaluate B\xE9zier
  vec2 result = curvedS_cubicBezier(t, src, c1, c2, tgt);

  // Rotate back to world space if needed
  if (!CURVEDS_ROTATE_WITH_CAMERA) {
    result = curvedS_rotate(result, u_cameraAngle);
  }

  return result;
}
`);return{name:"curvedS",segments:e,minBodyLengthRatio:0,glsl:f,uniforms:[],attributes:[]}}function nd(n){var a=n??{},t=a.orientation,e=t===void 0?"automatic":t,r=a.rotateWithCamera,i=r===void 0?!1:r,o=a.offset,s=o===void 0?.5:o,l=a.innerCornerSkipFactor,u=l===void 0?1:l,d,c=0;typeof e=="number"?(d=3,c=e):e==="horizontal"?d=1:e==="vertical"?d=2:d=0;var p=`
// Step path constants (baked from options)
const float STEP_OFFSET = `.concat(Y(s),`;
const int STEP_ORIENTATION = `).concat(d,`;
const float STEP_FIXED_ANGLE = `).concat(Y(c),`;
const bool STEP_ROTATE_WITH_CAMERA = `).concat(i?"true":"false",`;

`).concat(ur("step"),`

// ============================================================================
// HELPER: Get step segment points (source, corner1, corner2, target)
// ============================================================================
void getStepSegmentPoints(vec2 source, vec2 target, out vec2 c1, out vec2 c2) {
  vec2 delta = target - source;

  // Determine orientation
  bool horizontalFirst;
  if (STEP_ORIENTATION == 1) {
    horizontalFirst = true;
  } else if (STEP_ORIENTATION == 2) {
    horizontalFirst = false;
  } else if (STEP_ORIENTATION == 3) {
    // Fixed angle mode: first segment goes in fixed direction
    vec2 dir = vec2(cos(STEP_FIXED_ANGLE), sin(STEP_FIXED_ANGLE));
    float projLen = dot(delta, dir) * STEP_OFFSET;
    c1 = source + dir * projLen;
    // Last segment goes in same fixed direction
    c2 = target - dir * (dot(delta, dir) * (1.0 - STEP_OFFSET));
    return;
  } else {
    // Automatic: choose based on which delta is larger
    horizontalFirst = abs(delta.x) >= abs(delta.y);
  }

  if (horizontalFirst) {
    // H\u2192V\u2192H pattern
    float midX = source.x + delta.x * STEP_OFFSET;
    c1 = vec2(midX, source.y);
    c2 = vec2(midX, target.y);
  } else {
    // V\u2192H\u2192V pattern
    float midY = source.y + delta.y * STEP_OFFSET;
    c1 = vec2(source.x, midY);
    c2 = vec2(target.x, midY);
  }
}

// ============================================================================
// POSITION - Core function for vertex placement
// ============================================================================
vec2 path_step_position(float t, vec2 source, vec2 target) {
  // Apply camera rotation if not rotating with camera
  vec2 src = source;
  vec2 tgt = target;
  if (!STEP_ROTATE_WITH_CAMERA) {
    src = step_rotate(source, -u_cameraAngle);
    tgt = step_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Handle degenerate case (aligned nodes) -> straight line
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    vec2 result = mix(src, tgt, t);
    if (!STEP_ROTATE_WITH_CAMERA) {
      result = step_rotate(result, u_cameraAngle);
    }
    return result;
  }

  // Get segment points
  vec2 c1, c2;
  getStepSegmentPoints(src, tgt, c1, c2);

  // Compute segment lengths
  float L1 = length(c1 - src);
  float L2 = length(c2 - c1);
  float L3 = length(tgt - c2);
  float totalLen = L1 + L2 + L3;

  // Find position along path
  float dist = t * totalLen;
  vec2 result;

  if (dist <= L1) {
    float localT = dist / max(L1, 0.0001);
    result = mix(src, c1, localT);
  } else if (dist <= L1 + L2) {
    float localT = (dist - L1) / max(L2, 0.0001);
    result = mix(c1, c2, localT);
  } else {
    float localT = (dist - L1 - L2) / max(L3, 0.0001);
    result = mix(c2, tgt, localT);
  }

  // Rotate back to world space if needed
  if (!STEP_ROTATE_WITH_CAMERA) {
    result = step_rotate(result, u_cameraAngle);
  }

  return result;
}

// ============================================================================
// LENGTH - Total path length
// ============================================================================
float path_step_length(vec2 source, vec2 target) {
  // Apply camera rotation if not rotating with camera
  vec2 src = source;
  vec2 tgt = target;
  if (!STEP_ROTATE_WITH_CAMERA) {
    src = step_rotate(source, -u_cameraAngle);
    tgt = step_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Handle degenerate case
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    return length(delta);
  }

  vec2 c1, c2;
  getStepSegmentPoints(src, tgt, c1, c2);

  return length(c1 - src) + length(c2 - c1) + length(tgt - c2);
}
`),v=`
// ============================================================================
// ANALYTICAL TANGENT - Exact segment direction with narrow blend at corners
// ============================================================================
// This provides precise tangent computation for edge labels, avoiding the
// 45-degree rotation artifacts that numerical differentiation causes at corners.

vec2 path_step_tangent(float t, vec2 source, vec2 target) {
  // Apply camera rotation if not rotating with camera
  vec2 src = source;
  vec2 tgt = target;
  if (!STEP_ROTATE_WITH_CAMERA) {
    src = step_rotate(source, -u_cameraAngle);
    tgt = step_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Handle degenerate case (aligned nodes) -> straight line
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    vec2 dir = length(delta) > 0.0001 ? normalize(delta) : vec2(1.0, 0.0);
    if (!STEP_ROTATE_WITH_CAMERA) {
      dir = step_rotate(dir, u_cameraAngle);
    }
    return dir;
  }

  // Get segment points
  vec2 c1, c2;
  getStepSegmentPoints(src, tgt, c1, c2);

  // Compute segment lengths and corner t values
  float L1 = length(c1 - src);
  float L2 = length(c2 - c1);
  float L3 = length(tgt - c2);
  float totalLen = L1 + L2 + L3;

  float tCorner1 = L1 / totalLen;
  float tCorner2 = (L1 + L2) / totalLen;

  // Segment directions
  vec2 dir1 = normalize(c1 - src);
  vec2 dir2 = normalize(c2 - c1);
  vec2 dir3 = normalize(tgt - c2);

  // Narrow blend zone at corners (2% of total t range)
  // This creates a smooth transition over a few characters at corners
  float blendZone = 0.02;

  vec2 tangent;
  if (t < tCorner1 - blendZone) {
    tangent = dir1;
  } else if (t < tCorner1 + blendZone) {
    float blend = smoothstep(tCorner1 - blendZone, tCorner1 + blendZone, t);
    tangent = normalize(mix(dir1, dir2, blend));
  } else if (t < tCorner2 - blendZone) {
    tangent = dir2;
  } else if (t < tCorner2 + blendZone) {
    float blend = smoothstep(tCorner2 - blendZone, tCorner2 + blendZone, t);
    tangent = normalize(mix(dir2, dir3, blend));
  } else {
    tangent = dir3;
  }

  // Rotate back to world space if needed
  if (!STEP_ROTATE_WITH_CAMERA) {
    tangent = step_rotate(tangent, u_cameraAngle);
  }

  return tangent;
}

// Normal is perpendicular to tangent
vec2 path_step_normal(float t, vec2 source, vec2 target) {
  vec2 tangent = path_step_tangent(t, source, target);
  return vec2(-tangent.y, tangent.x);
}
`,f=`
// ============================================================================
// CORNER SKIP HELPERS - For above/below label positioning on step edges
// ============================================================================
// When labels are positioned above or below a step edge, characters can
// overlap at "concave" corners (inner side of the bend). These helpers
// detect concave corners and compute skip distances to create gaps.

// Constant for inner corner skip factor (baked from options)
const float STEP_INNER_CORNER_SKIP_FACTOR = `.concat(Y(u),`;

// Returns the t values for the two corners of the step path.
// x = t at corner 1 (between segment A and B)
// y = t at corner 2 (between segment B and C)
vec2 path_step_getCornerTs(vec2 source, vec2 target) {
  vec2 src = source;
  vec2 tgt = target;
  if (!STEP_ROTATE_WITH_CAMERA) {
    src = step_rotate(source, -u_cameraAngle);
    tgt = step_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Degenerate case: no real corners
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    return vec2(0.5, 0.5);
  }

  vec2 c1, c2;
  getStepSegmentPoints(src, tgt, c1, c2);

  float L1 = length(c1 - src);
  float L2 = length(c2 - c1);
  float L3 = length(tgt - c2);
  float totalLen = L1 + L2 + L3;

  return vec2(L1 / totalLen, (L1 + L2) / totalLen);
}

// Determines which corners are concave relative to the label position.
// A corner is "concave" for a label if the label is on the inner side of the bend.
//
// perpOffset > 0 means "above" (left side of path direction in screen coords)
// perpOffset < 0 means "below" (right side of path direction)
//
// Returns: x = 1.0 if corner 1 is concave, 0.0 otherwise
//          y = 1.0 if corner 2 is concave, 0.0 otherwise
vec2 path_step_getCornerConcavity(vec2 source, vec2 target, float perpOffset) {
  if (abs(perpOffset) < 0.0001) {
    return vec2(0.0); // Centerline mode - no corners to skip
  }

  vec2 src = source;
  vec2 tgt = target;
  if (!STEP_ROTATE_WITH_CAMERA) {
    src = step_rotate(source, -u_cameraAngle);
    tgt = step_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;

  // Degenerate case: no corners
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    return vec2(0.0);
  }

  vec2 c1, c2;
  getStepSegmentPoints(src, tgt, c1, c2);

  // Segment directions (in rotated space)
  vec2 dir1 = normalize(c1 - src);
  vec2 dir2 = normalize(c2 - c1);
  vec2 dir3 = normalize(tgt - c2);

  // Cross product gives bend direction:
  // Positive = counter-clockwise turn (left turn)
  // Negative = clockwise turn (right turn)
  // cross(a, b) = a.x * b.y - a.y * b.x
  float bend1 = dir1.x * dir2.y - dir1.y * dir2.x;
  float bend2 = dir2.x * dir3.y - dir2.y * dir3.x;

  // A corner is concave for the label if:
  // - The bend goes one way (CW or CCW)
  // - The label is on the same side as the bend (inside the bend)
  //
  // When bend is positive (CCW/left turn) and perpOffset > 0 (above/left side),
  // the label is on the INNER side (concave) - skip needed.
  //
  // When bend is positive (CCW/left turn) and perpOffset < 0 (below/right side),
  // the label is on the OUTER side (convex) - no skip needed.
  //
  // Formula: concave if (bend * perpOffset) > 0
  float concave1 = (bend1 * perpOffset > 0.0) ? 1.0 : 0.0;
  float concave2 = (bend2 * perpOffset > 0.0) ? 1.0 : 0.0;

  return vec2(concave1, concave2);
}
`);return{name:"step",segments:64,minBodyLengthRatio:2,linearParameterization:!0,glsl:p,analyticalTangentGlsl:v,cornerSkipGlsl:f,hasSharpCorners:!0,innerCornerSkipFactor:u,uniforms:[],attributes:[]}}function ad(n){var a=n??{},t=a.orientation,e=t===void 0?"automatic":t,r=a.rotateWithCamera,i=r===void 0?!1:r,o=a.offset,s=o===void 0?.5:o,l=a.cornerRadius,u=l===void 0?.4:l,d,c=0;typeof e=="number"?(d=3,c=e):e==="horizontal"?d=1:e==="vertical"?d=2:d=0;var p=`
// Step curved path constants (baked from options)
const float STEPC_OFFSET = `.concat(Y(s),`;
const int STEPC_ORIENTATION = `).concat(d,`;
const float STEPC_FIXED_ANGLE = `).concat(Y(c),`;
const bool STEPC_ROTATE_WITH_CAMERA = `).concat(i?"true":"false",`;
const float STEPC_CORNER_RATIO = `).concat(Y(u),`;

`).concat(ur("stepC"),`

// ============================================================================
// HELPER: Get taxi segment points with corner radius info
// ============================================================================
void getStepCSegmentPoints(vec2 source, vec2 target, out vec2 c1, out vec2 c2, out float cornerRadius) {
  vec2 delta = target - source;

  // Determine orientation
  bool horizontalFirst;
  if (STEPC_ORIENTATION == 1) {
    horizontalFirst = true;
  } else if (STEPC_ORIENTATION == 2) {
    horizontalFirst = false;
  } else if (STEPC_ORIENTATION == 3) {
    vec2 dir = vec2(cos(STEPC_FIXED_ANGLE), sin(STEPC_FIXED_ANGLE));
    float projLen = dot(delta, dir) * STEPC_OFFSET;
    c1 = source + dir * projLen;
    c2 = target - dir * (dot(delta, dir) * (1.0 - STEPC_OFFSET));
    float L1 = length(c1 - source);
    float L2 = length(c2 - c1);
    float L3 = length(target - c2);
    cornerRadius = min(min(L1, L2 * 0.5), L3) * STEPC_CORNER_RATIO;
    return;
  } else {
    horizontalFirst = abs(delta.x) >= abs(delta.y);
  }

  if (horizontalFirst) {
    float midX = source.x + delta.x * STEPC_OFFSET;
    c1 = vec2(midX, source.y);
    c2 = vec2(midX, target.y);
  } else {
    float midY = source.y + delta.y * STEPC_OFFSET;
    c1 = vec2(source.x, midY);
    c2 = vec2(target.x, midY);
  }

  // Compute corner radius based on shortest segment
  float L1 = length(c1 - source);
  float L2 = length(c2 - c1);
  float L3 = length(target - c2);
  cornerRadius = min(min(L1, L2 * 0.5), L3) * STEPC_CORNER_RATIO;
}

// ============================================================================
// HELPER: Quadratic bezier evaluation
// ============================================================================
vec2 stepC_bezier(vec2 p0, vec2 p1, vec2 p2, float t) {
  float mt = 1.0 - t;
  return mt * mt * p0 + 2.0 * mt * t * p1 + t * t * p2;
}

vec2 stepC_bezierTangent(vec2 p0, vec2 p1, vec2 p2, float t) {
  return normalize(2.0 * (1.0 - t) * (p1 - p0) + 2.0 * t * (p2 - p1));
}

float stepC_bezierLength(vec2 p0, vec2 p1, vec2 p2) {
  // Approximate length using 8 samples
  float len = 0.0;
  vec2 prev = p0;
  for (int i = 1; i <= 8; i++) {
    float t = float(i) / 8.0;
    vec2 curr = stepC_bezier(p0, p1, p2, t);
    len += length(curr - prev);
    prev = curr;
  }
  return len;
}

// ============================================================================
// PATH LENGTH - Total path length with rounded corners
// ============================================================================
float path_stepCurved_length(vec2 source, vec2 target) {
  vec2 src = source;
  vec2 tgt = target;
  if (!STEPC_ROTATE_WITH_CAMERA) {
    src = stepC_rotate(source, -u_cameraAngle);
    tgt = stepC_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    return length(delta);
  }

  vec2 c1, c2;
  float r;
  getStepCSegmentPoints(src, tgt, c1, c2, r);

  // Segment lengths (shortened by corner radius on each end)
  float L1 = max(length(c1 - src) - r, 0.0);
  float L2 = max(length(c2 - c1) - 2.0 * r, 0.0);
  float L3 = max(length(tgt - c2) - r, 0.0);

  // Corner arc lengths
  vec2 dir1 = normalize(c1 - src);
  vec2 dir2 = normalize(c2 - c1);
  vec2 dir3 = normalize(tgt - c2);

  vec2 corner1_start = c1 - dir1 * r;
  vec2 corner1_end = c1 + dir2 * r;
  vec2 corner2_start = c2 - dir2 * r;
  vec2 corner2_end = c2 + dir3 * r;

  float arc1 = stepC_bezierLength(corner1_start, c1, corner1_end);
  float arc2 = stepC_bezierLength(corner2_start, c2, corner2_end);

  return L1 + arc1 + L2 + arc2 + L3;
}

// ============================================================================
// POSITION - Position along rounded path
// ============================================================================
vec2 path_stepCurved_position(float t, vec2 source, vec2 target) {
  vec2 src = source;
  vec2 tgt = target;
  if (!STEPC_ROTATE_WITH_CAMERA) {
    src = stepC_rotate(source, -u_cameraAngle);
    tgt = stepC_rotate(target, -u_cameraAngle);
  }

  vec2 delta = tgt - src;
  if (abs(delta.x) < 0.0001 || abs(delta.y) < 0.0001) {
    vec2 result = mix(src, tgt, t);
    if (!STEPC_ROTATE_WITH_CAMERA) {
      result = stepC_rotate(result, u_cameraAngle);
    }
    return result;
  }

  vec2 c1, c2;
  float r;
  getStepCSegmentPoints(src, tgt, c1, c2, r);

  vec2 dir1 = normalize(c1 - src);
  vec2 dir2 = normalize(c2 - c1);
  vec2 dir3 = normalize(tgt - c2);

  // Key points
  vec2 seg1_end = c1 - dir1 * r;
  vec2 corner1_end = c1 + dir2 * r;
  vec2 seg2_end = c2 - dir2 * r;
  vec2 corner2_end = c2 + dir3 * r;

  // Segment lengths
  float L1 = length(seg1_end - src);
  float arc1 = stepC_bezierLength(seg1_end, c1, corner1_end);
  float L2 = length(seg2_end - corner1_end);
  float arc2 = stepC_bezierLength(seg2_end, c2, corner2_end);
  float L3 = length(tgt - corner2_end);
  float totalLen = L1 + arc1 + L2 + arc2 + L3;

  float dist = t * totalLen;
  vec2 result;

  if (dist <= L1) {
    float localT = dist / max(L1, 0.0001);
    result = mix(src, seg1_end, localT);
  } else if (dist <= L1 + arc1) {
    float localDist = dist - L1;
    float localT = localDist / max(arc1, 0.0001);
    result = stepC_bezier(seg1_end, c1, corner1_end, localT);
  } else if (dist <= L1 + arc1 + L2) {
    float localDist = dist - L1 - arc1;
    float localT = localDist / max(L2, 0.0001);
    result = mix(corner1_end, seg2_end, localT);
  } else if (dist <= L1 + arc1 + L2 + arc2) {
    float localDist = dist - L1 - arc1 - L2;
    float localT = localDist / max(arc2, 0.0001);
    result = stepC_bezier(seg2_end, c2, corner2_end, localT);
  } else {
    float localDist = dist - L1 - arc1 - L2 - arc2;
    float localT = localDist / max(L3, 0.0001);
    result = mix(corner2_end, tgt, localT);
  }

  if (!STEPC_ROTATE_WITH_CAMERA) {
    result = stepC_rotate(result, u_cameraAngle);
  }
  return result;
}
`);return{name:"stepCurved",segments:32,glsl:p,uniforms:[],attributes:[]}}function rd(n){var a=n??{},t=a.lengthRatio,e=t===void 0?5:t,r=a.widthRatio,i=r===void 0?4:r,o=a.margin,s=o===void 0?0:o,l=`
// Arrow SDF: triangle with base at x=0, tip at x=lengthRatio
// uv.x: 0 (base) to lengthRatio (tip), uv.y: [-halfW, +halfW]
// Returns signed distance (negative inside, positive outside)
float extremity_arrow(vec2 uv, float lengthRatio, float widthRatio) {
  float x = uv.x;
  float y = abs(uv.y);
  float halfW = widthRatio * 0.5;

  // Past the tip: euclidean distance to tip point
  if (x > lengthRatio) {
    return length(vec2(x - lengthRatio, y));
  }

  // Back edge: signed distance to x=0 line
  float backDist = -x;

  // Side edge: signed distance to sloped triangle edge
  float clampedX = max(0.0, x);
  float maxY = halfW * (1.0 - clampedX / lengthRatio);
  float sideDist = y - maxY;

  // Convex shape SDF = max of half-plane distances
  return max(backDist, sideDist);
}
`;return{name:"arrow",glsl:l,length:e,widthFactor:i,margin:s,uniforms:[],attributes:[]}}function id(n){var a=n??{},t=a.lengthRatio,e=t===void 0?.75:t,r=a.widthRatio,i=r===void 0?4:r,o=a.margin,s=o===void 0?0:o,l=`
// Box SDF (same geometry as square, different defaults)
float extremity_bar(vec2 uv, float lengthRatio, float widthRatio) {
  float halfW = widthRatio * 0.5;

  // Box SDF: distance to rectangle [0, lengthRatio] \xD7 [-halfW, halfW]
  vec2 center = vec2(lengthRatio * 0.5, 0.0);
  vec2 halfSize = vec2(lengthRatio * 0.5, halfW);
  vec2 d = abs(uv - center) - halfSize;
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0);
}
`;return{name:"bar",glsl:l,length:e,widthFactor:i,margin:s,baseRatio:1,uniforms:[],attributes:[]}}function od(n){var a=n??{},t=a.lengthRatio,e=t===void 0?4:t,r=a.widthRatio,i=r===void 0?e+1:r,o=a.margin,s=o===void 0?0:o,l=`
// Circle SDF: circle centered at (lengthRatio/2, 0) with radius = lengthRatio/2
// uv.x: 0 (base) to lengthRatio (far edge), uv.y: [-halfW, +halfW]
float extremity_circle(vec2 uv, float lengthRatio, float widthRatio) {
  float radius = lengthRatio * 0.5;
  vec2 center = vec2(radius, 0.0);
  return length(uv - center) - radius;
}
`;return{name:"circle",glsl:l,length:e,widthFactor:i,margin:s,uniforms:[],attributes:[]}}function sd(n){var a=n??{},t=a.lengthRatio,e=t===void 0?5:t,r=a.widthRatio,i=r===void 0?4:r,o=a.margin,s=o===void 0?0:o,l=`
// Diamond SDF: rhombus with vertices at (0,0), (L/2, W/2), (L, 0), (L/2, -W/2)
float extremity_diamond(vec2 uv, float lengthRatio, float widthRatio) {
  float halfL = lengthRatio * 0.5;
  float halfW = widthRatio * 0.5;

  // Center the diamond at (halfL, 0)
  vec2 p = abs(uv - vec2(halfL, 0.0));

  // Diamond is the set |x/halfL| + |y/halfW| <= 1
  // Signed distance: (p.x/halfL + p.y/halfW - 1) * normalization
  float d = p.x / halfL + p.y / halfW - 1.0;

  // Scale by the distance from center to edge along the gradient direction
  float norm = length(vec2(1.0 / halfL, 1.0 / halfW));
  return d / norm;
}
`;return{name:"diamond",glsl:l,length:e,widthFactor:i,margin:s,uniforms:[],attributes:[]}}function ld(n){var a=n??{},t=a.lengthRatio,e=t===void 0?4:t,r=a.widthRatio,i=r===void 0?4:r,o=a.margin,s=o===void 0?0:o,l=`
// Box SDF (same geometry as bar, different defaults)
float extremity_square(vec2 uv, float lengthRatio, float widthRatio) {
  float halfW = widthRatio * 0.5;
  vec2 center = vec2(lengthRatio * 0.5, 0.0);
  vec2 halfSize = vec2(lengthRatio * 0.5, halfW);
  vec2 d = abs(uv - center) - halfSize;
  return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0);
}
`;return{name:"square",glsl:l,length:e,widthFactor:i,margin:s,baseRatio:1,uniforms:[],attributes:[]}}var Do=8,ud=(function(){function n(a){X(this,n),S(this,"program",null),S(this,"vao",null),S(this,"drawFramebuffer",null),S(this,"readFramebuffer",null),S(this,"viewport",new Int32Array(4)),S(this,"blend",!1),S(this,"blendSrcRGB",WebGL2RenderingContext.ONE),S(this,"blendDstRGB",WebGL2RenderingContext.ZERO),S(this,"blendSrcAlpha",WebGL2RenderingContext.ONE),S(this,"blendDstAlpha",WebGL2RenderingContext.ZERO),S(this,"blendEquationRGB",WebGL2RenderingContext.FUNC_ADD),S(this,"blendEquationAlpha",WebGL2RenderingContext.FUNC_ADD),S(this,"colorMask",[!0,!0,!0,!0]),S(this,"activeTexture",WebGL2RenderingContext.TEXTURE0),S(this,"textures",[]),this.gl=a}return j(n,[{key:"save",value:function(){var t=this.gl;this.program=t.getParameter(t.CURRENT_PROGRAM),this.vao=t.getParameter(t.VERTEX_ARRAY_BINDING),this.drawFramebuffer=t.getParameter(t.DRAW_FRAMEBUFFER_BINDING),this.readFramebuffer=t.getParameter(t.READ_FRAMEBUFFER_BINDING),this.viewport=t.getParameter(t.VIEWPORT),this.blend=t.isEnabled(t.BLEND),this.blendSrcRGB=t.getParameter(t.BLEND_SRC_RGB),this.blendDstRGB=t.getParameter(t.BLEND_DST_RGB),this.blendSrcAlpha=t.getParameter(t.BLEND_SRC_ALPHA),this.blendDstAlpha=t.getParameter(t.BLEND_DST_ALPHA),this.blendEquationRGB=t.getParameter(t.BLEND_EQUATION_RGB),this.blendEquationAlpha=t.getParameter(t.BLEND_EQUATION_ALPHA),this.colorMask=t.getParameter(t.COLOR_WRITEMASK),this.activeTexture=t.getParameter(t.ACTIVE_TEXTURE);for(var e=0;e<Do;e++)t.activeTexture(t.TEXTURE0+e),this.textures[e]=t.getParameter(t.TEXTURE_BINDING_2D);t.activeTexture(this.activeTexture)}},{key:"restore",value:function(){for(var t=this.gl,e=0;e<Do;e++)t.activeTexture(t.TEXTURE0+e),t.bindTexture(t.TEXTURE_2D,this.textures[e]);t.activeTexture(this.activeTexture),t.useProgram(this.program),t.bindVertexArray(this.vao),t.bindFramebuffer(t.DRAW_FRAMEBUFFER,this.drawFramebuffer),t.bindFramebuffer(t.READ_FRAMEBUFFER,this.readFramebuffer),t.viewport(this.viewport[0],this.viewport[1],this.viewport[2],this.viewport[3]),this.blend?t.enable(t.BLEND):t.disable(t.BLEND),t.blendFuncSeparate(this.blendSrcRGB,this.blendDstRGB,this.blendSrcAlpha,this.blendDstAlpha),t.blendEquationSeparate(this.blendEquationRGB,this.blendEquationAlpha),t.colorMask(this.colorMask[0],this.colorMask[1],this.colorMask[2],this.colorMask[3]),t.bindBuffer(t.PIXEL_PACK_BUFFER,null)}}])})();var Ar={};ha(Ar,{ANIMATE_DEFAULTS:()=>Gt,HTML_COLORS:()=>je,addPositionToDepthRanges:()=>Wt,animateNodes:()=>_i,assign:()=>En,colorToArray:()=>xe,colorToGLSLString:()=>mn,colorToIndex:()=>wt,colorToVec4:()=>ut,createElement:()=>Ne,createNormalizationFunction:()=>pt,cubicIn:()=>_a,cubicInOut:()=>Sa,cubicOut:()=>Ta,easings:()=>ft,exponentialIn:()=>Ea,exponentialInOut:()=>Aa,exponentialOut:()=>Ra,extend:()=>Mt,floatColor:()=>ie,getCorrectionRatio:()=>fa,getMatrixImpact:()=>gn,getPixelColor:()=>vn,getPixelRatio:()=>$e,hasBackdrop:()=>Ot,hasForcedLabel:()=>ye,hasNewPartialProps:()=>ze,identity:()=>re,indexToColor:()=>Ie,linear:()=>pa,matrixFromCamera:()=>be,multiply:()=>pe,multiplyVec2:()=>we,nodeRotationFlags:()=>mt,packItemsOnPage:()=>Zn,parseColor:()=>lt,parseFontString:()=>bt,pickingPixelCoords:()=>Ft,quadraticIn:()=>ba,quadraticInOut:()=>ya,quadraticOut:()=>xa,removePositionFromDepthRanges:()=>Bt,resolveEasing:()=>ke,rgbaToFloat:()=>ga,rotate:()=>cn,rotateVec2:()=>Pt,scale:()=>ot,setMembership:()=>Ae,shallowEqual:()=>Rn,translate:()=>hn,validateGraph:()=>Dn});var Uc=Se(An());var zo=Se(Ze());var Kc=Se(Ze());function ra(n,a){return{type:"number",default:n,variable:a?.variable}}function Co(n,a){return{type:"color",default:n,variable:a?.variable}}function ia(n,a){return{type:"string",default:n,variable:a?.variable}}function Lo(n,a){return{type:"boolean",default:n,variable:a?.variable}}function oa(n,a){return{type:{enum:n},default:a,variable:!1}}function Po(n,a){return{type:"array",items:n,minItems:a?.minItems}}function Dr(n,a){(a==null||a>n.length)&&(a=n.length);for(var t=0,e=Array(a);t<a;t++)e[t]=n[t];return e}function No(n,a){if(n){if(typeof n=="string")return Dr(n,a);var t={}.toString.call(n).slice(8,-1);return t==="Object"&&n.constructor&&(t=n.constructor.name),t==="Map"||t==="Set"?Array.from(n):t==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)?Dr(n,a):void 0}}function dd(n,a){var t=typeof Symbol<"u"&&n[Symbol.iterator]||n["@@iterator"];if(!t){if(Array.isArray(n)||(t=No(n))||a&&n&&typeof n.length=="number"){t&&(n=t);var e=0,r=function(){};return{s:r,n:function(){return e>=n.length?{done:!0}:{done:!1,value:n[e++]}},e:function(l){throw l},f:r}}throw new TypeError(`Invalid attempt to iterate non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}var i,o=!0,s=!1;return{s:function(){t=t.call(n)},n:function(){var l=t.next();return o=l.done,l},e:function(l){s=!0,i=l},f:function(){try{o||t.return==null||t.return()}finally{if(s)throw i}}}}function cd(n,a){if(n==null)return{};var t={};for(var e in n)if({}.hasOwnProperty.call(n,e)){if(a.indexOf(e)!==-1)continue;t[e]=n[e]}return t}function hd(n,a){if(n==null)return{};var t,e,r=cd(n,a);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(n);for(e=0;e<i.length;e++)t=i[e],a.indexOf(t)===-1&&{}.propertyIsEnumerable.call(n,t)&&(r[t]=n[t])}return r}function fd(n,a){if(typeof n!="object"||!n)return n;var t=n[Symbol.toPrimitive];if(t!==void 0){var e=t.call(n,a||"default");if(typeof e!="object")return e;throw new TypeError("@@toPrimitive must return a primitive value.")}return(a==="string"?String:Number)(n)}function Mo(n){var a=fd(n,"string");return typeof a=="symbol"?a:a+""}function Fe(n,a,t){return(a=Mo(a))in n?Object.defineProperty(n,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):n[a]=t,n}function Fo(n,a){var t=Object.keys(n);if(Object.getOwnPropertySymbols){var e=Object.getOwnPropertySymbols(n);a&&(e=e.filter(function(r){return Object.getOwnPropertyDescriptor(n,r).enumerable})),t.push.apply(t,e)}return t}function ae(n){for(var a=1;a<arguments.length;a++){var t=arguments[a]!=null?arguments[a]:{};a%2?Fo(Object(t),!0).forEach(function(e){Fe(n,e,t[e])}):Object.getOwnPropertyDescriptors?Object.defineProperties(n,Object.getOwnPropertyDescriptors(t)):Fo(Object(t)).forEach(function(e){Object.defineProperty(n,e,Object.getOwnPropertyDescriptor(t,e))})}return n}function gd(n){if(Array.isArray(n))return Dr(n)}function vd(n){if(typeof Symbol<"u"&&n[Symbol.iterator]!=null||n["@@iterator"]!=null)return Array.from(n)}function md(){throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function wr(n){return gd(n)||vd(n)||No(n)||md()}function de(n,a,t,e){var r=Object.defineProperty;try{r({},"",{})}catch{r=0}de=function(i,o,s,l){function u(d,c){de(i,d,function(p){return this._invoke(d,c,p)})}o?r?r(i,o,{value:s,enumerable:!l,configurable:!l,writable:!l}):i[o]=s:(u("next",0),u("throw",1),u("return",2))},de(n,a,t,e)}function rt(){var n,a,t=typeof Symbol=="function"?Symbol:{},e=t.iterator||"@@iterator",r=t.toStringTag||"@@toStringTag";function i(v,f,b,g){var h=f&&f.prototype instanceof s?f:s,m=Object.create(h.prototype);return de(m,"_invoke",(function(x,y,_){var T,R,E,D=0,P=_||[],w=!1,A={p:0,n:0,v:n,a:F,f:F.bind(n,4),d:function(L,k){return T=L,R=0,E=n,A.n=k,o}};function F(L,k){for(R=L,E=k,a=0;!w&&D&&!N&&a<P.length;a++){var N,z=P[a],I=A.p,C=z[2];L>3?(N=C===k)&&(E=z[(R=z[4])?5:(R=3,3)],z[4]=z[5]=n):z[0]<=I&&((N=L<2&&I<z[1])?(R=0,A.v=k,A.n=z[1]):I<C&&(N=L<3||z[0]>k||k>C)&&(z[4]=L,z[5]=k,A.n=C,R=0))}if(N||L>1)return o;throw w=!0,k}return function(L,k,N){if(D>1)throw TypeError("Generator is already running");for(w&&k===1&&F(k,N),R=k,E=N;(a=R<2?n:E)||!w;){T||(R?R<3?(R>1&&(A.n=-1),F(R,E)):A.n=E:A.v=E);try{if(D=2,T){if(R||(L="next"),a=T[L]){if(!(a=a.call(T,E)))throw TypeError("iterator result is not an object");if(!a.done)return a;E=a.value,R<2&&(R=0)}else R===1&&(a=T.return)&&a.call(T),R<2&&(E=TypeError("The iterator does not provide a '"+L+"' method"),R=1);T=n}else if((a=(w=A.n<0)?E:x.call(y,A))!==o)break}catch(z){T=n,R=1,E=z}finally{D=1}}return{value:a,done:w}}})(v,b,g),!0),m}var o={};function s(){}function l(){}function u(){}a=Object.getPrototypeOf;var d=[][e]?a(a([][e]())):(de(a={},e,function(){return this}),a),c=u.prototype=s.prototype=Object.create(d);function p(v){return Object.setPrototypeOf?Object.setPrototypeOf(v,u):(v.__proto__=u,de(v,r,"GeneratorFunction")),v.prototype=Object.create(c),v}return l.prototype=u,de(c,"constructor",u),de(u,"constructor",l),l.displayName="GeneratorFunction",de(u,r,"GeneratorFunction"),de(c),de(c,r,"Generator"),de(c,e,function(){return this}),de(c,"toString",function(){return"[object Generator]"}),(rt=function(){return{w:i,m:p}})()}function la(n){return la=Object.setPrototypeOf?Object.getPrototypeOf.bind():function(a){return a.__proto__||Object.getPrototypeOf(a)},la(n)}function Go(){try{var n=!Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],function(){}))}catch{}return(Go=function(){return!!n})()}function pd(n){if(n===void 0)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return n}function bd(n,a){if(a&&(typeof a=="object"||typeof a=="function"))return a;if(a!==void 0)throw new TypeError("Derived constructors may only return object or undefined");return pd(n)}function xd(n,a,t){return a=la(a),bd(n,Go()?Reflect.construct(a,t||[],la(n).constructor):a.apply(n,t))}function Cr(n,a){return Cr=Object.setPrototypeOf?Object.setPrototypeOf.bind():function(t,e){return t.__proto__=e,t},Cr(n,a)}function yd(n,a){if(typeof a!="function"&&a!==null)throw new TypeError("Super expression must either be null or a function");n.prototype=Object.create(a&&a.prototype,{constructor:{value:n,writable:!0,configurable:!0}}),Object.defineProperty(n,"prototype",{writable:!1}),a&&Cr(n,a)}function Oo(n,a){if(!(n instanceof a))throw new TypeError("Cannot call a class as a function")}function wo(n,a){for(var t=0;t<a.length;t++){var e=a[t];e.enumerable=e.enumerable||!1,e.configurable=!0,"value"in e&&(e.writable=!0),Object.defineProperty(n,Mo(e.key),e)}}function Bo(n,a,t){return a&&wo(n.prototype,a),t&&wo(n,t),Object.defineProperty(n,"prototype",{writable:!1}),n}function Io(n,a,t,e,r,i,o){try{var s=n[i](o),l=s.value}catch(u){return void t(u)}s.done?a(l):Promise.resolve(l).then(e,r)}function Ir(n){return function(){var a=this,t=arguments;return new Promise(function(e,r){var i=n.apply(a,t);function o(l){Io(i,e,r,o,s,"next",l)}function s(l){Io(i,e,r,o,s,"throw",l)}o(void 0)})}}var kr={size:{mode:"max",value:512},objectFit:"cover",correctCentering:!1,maxTextureSize:4096,debounceTimeout:500,crossOrigin:"anonymous"},_d=1;function Lr(n){var a=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},t=a.crossOrigin;return new Promise(function(e,r){var i=new Image;i.addEventListener("load",function(){e(i)},{once:!0}),i.addEventListener("error",function(o){r(o.error)},{once:!0}),t&&i.setAttribute("crossOrigin",t),i.src=n})}function Td(n){return Pr.apply(this,arguments)}function Pr(){return Pr=Ir(rt().m(function n(a){var t,e,r,i,o,s,l,u,d,c,p,v,f,b=arguments;return rt().w(function(g){for(;;)switch(g.n){case 0:if(t=b.length>1&&b[1]!==void 0?b[1]:{},e=t.size,r=t.crossOrigin,r!=="use-credentials"){g.n=2;break}return g.n=1,fetch(a,{credentials:"include"});case 1:i=g.v,g.n=4;break;case 2:return g.n=3,fetch(a);case 3:i=g.v;case 4:return g.n=5,i.text();case 5:if(o=g.v,s=new DOMParser().parseFromString(o,"image/svg+xml"),l=s.documentElement,u=l.getAttribute("width"),d=l.getAttribute("height"),!(!u||!d)){g.n=6;break}throw new Error("loadSVGImage: cannot use `size` if target SVG has no definite dimensions.");case 6:return typeof e=="number"&&(l.setAttribute("width",""+e),l.setAttribute("height",""+e)),c=new XMLSerializer().serializeToString(s),p=new Blob([c],{type:"image/svg+xml"}),v=URL.createObjectURL(p),f=Lr(v),f.finally(function(){return URL.revokeObjectURL(v)}),g.a(2,f)}},n)})),Pr.apply(this,arguments)}function Sd(n){return Fr.apply(this,arguments)}function Fr(){return Fr=Ir(rt().m(function n(a){var t,e,r,i,o,s,l=arguments;return rt().w(function(u){for(;;)switch(u.p=u.n){case 0:if(e=l.length>1&&l[1]!==void 0?l[1]:{},r=e.size,i=e.crossOrigin,o=((t=a.split(/[#?]/)[0].split(".").pop())===null||t===void 0?void 0:t.trim().toLowerCase())==="svg",!(o&&r)){u.n=6;break}return u.p=1,u.n=2,Td(a,{size:r,crossOrigin:i});case 2:s=u.v,u.n=5;break;case 3:return u.p=3,u.v,u.n=4,Lr(a,{crossOrigin:i});case 4:s=u.v;case 5:u.n=8;break;case 6:return u.n=7,Lr(a,{crossOrigin:i});case 7:s=u.v;case 8:return u.a(2,s)}},n,null,[[1,3]])})),Fr.apply(this,arguments)}function Ed(n,a,t){var e=t.objectFit,r=t.size,i=t.correctCentering,o=e==="contain"?Math.max(n.width,n.height):Math.min(n.width,n.height),s=r.mode==="auto"?o:r.mode==="force"?r.value:Math.min(r.value,o),l=(n.width-o)/2,u=(n.height-o)/2;if(i){var d=a.getCorrectionOffset(n,o);l=d.x,u=d.y}return{sourceX:l,sourceY:u,sourceSize:o,destinationSize:s}}function Rd(n,a,t){for(var e=a.canvas,r=e.width,i=e.height,o=[],s=t.x,l=t.y,u=t.rowHeight,d=t.maxRowWidth,c={},p=0,v=n.length;p<v;p++){var f=n[p],b=f.key,g=f.image,h=f.sourceSize,m=f.sourceX,x=f.sourceY,y=f.destinationSize,_=y+_d;l+_>i||s+_>r&&l+_+u>i||(s+_>r&&(d=Math.max(d,s),s=0,l+=u,u=_),o.push({key:b,image:g,sourceX:m,sourceY:x,sourceSize:h,destinationX:s,destinationY:l,destinationSize:y}),c[b]={x:s,y:l,size:y},s+=_,u=Math.max(u,_))}d=Math.max(d,s);for(var T=d,R=l+u,E=0,D=o.length;E<D;E++){var P=o[E],w=P.image,A=P.sourceSize,F=P.sourceX,L=P.sourceY,k=P.destinationSize,N=P.destinationX,z=P.destinationY;a.drawImage(w,F,L,A,A,N,z,k,k)}return{atlas:c,texture:a.getImageData(0,0,T,R),cursor:{x:s,y:l,rowHeight:u,maxRowWidth:d}}}function Ad(n,a,t){var e=n.atlas,r=n.textures,i=n.cursor,o={atlas:ae({},e),textures:wr(r.slice(0,-1)),cursor:ae({},i)},s=[];for(var l in a){var u,d=a[l];if(d.status==="ready"){var c=(u=e[l])===null||u===void 0?void 0:u.textureIndex;typeof c!="number"&&s.push(ae({key:l},d))}}for(var p=function(){var f=Rd(s,t,o.cursor),b=f.atlas,g=f.texture,h=f.cursor;o.cursor=h;var m=[];s.forEach(function(x){b[x.key]?o.atlas[x.key]=ae(ae({},b[x.key]),{},{textureIndex:o.textures.length}):m.push(x)}),o.textures.push(g),s=m,s.length&&(o.cursor={x:0,y:0,rowHeight:0,maxRowWidth:0},t.clearRect(0,0,t.canvas.width,t.canvas.height))};s.length;)p();return o}var Dd=(function(){function n(){Oo(this,n),this.canvas=document.createElement("canvas"),this.context=this.canvas.getContext("2d",{willReadFrequently:!0})}return Bo(n,[{key:"getCorrectionOffset",value:function(t,e){this.canvas.width=e,this.canvas.height=e,this.context.clearRect(0,0,e,e),this.context.drawImage(t,0,0,e,e);for(var r=this.context.getImageData(0,0,e,e).data,i=new Uint8ClampedArray(r.length/4),o=0;o<r.length;o++)i[o]=r[o*4+3];for(var s=0,l=0,u=0,d=0;d<e;d++)for(var c=0;c<e;c++){var p=i[d*e+c];u+=p,s+=p*c,l+=p*d}var v=s/u,f=l/u;return{x:v-e/2,y:f-e/2}}}])})(),sa=(function(n){function a(){var t,e=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};return Oo(this,a),t=xd(this,a),Fe(t,"canvas",document.createElement("canvas")),Fe(t,"ctx",t.canvas.getContext("2d",{willReadFrequently:!0})),Fe(t,"corrector",new Dd),Fe(t,"imageStates",{}),Fe(t,"textures",[t.ctx.getImageData(0,0,1,1)]),Fe(t,"lastTextureCursor",{x:0,y:0,rowHeight:0,maxRowWidth:0}),Fe(t,"atlas",{}),t.options=ae(ae({},kr),e),t.canvas.width=t.options.maxTextureSize,t.canvas.height=t.options.maxTextureSize,t}return yd(a,n),Bo(a,[{key:"scheduleGenerateTexture",value:function(){var e=this;typeof this.frameId!="number"&&(typeof this.options.debounceTimeout=="number"?this.frameId=window.setTimeout(function(){e.generateTextures(),e.frameId=void 0},this.options.debounceTimeout):this.generateTextures())}},{key:"generateTextures",value:function(){var e=Ad({atlas:this.atlas,textures:this.textures,cursor:this.lastTextureCursor},this.imageStates,this.ctx),r=e.atlas,i=e.textures,o=e.cursor;this.atlas=r,this.textures=i,this.lastTextureCursor=o,this.emit(a.NEW_TEXTURE_EVENT,{atlas:r,textures:i})}},{key:"registerImage",value:(function(){var t=Ir(rt().m(function r(i){var o,s;return rt().w(function(l){for(;;)switch(l.p=l.n){case 0:if(!this.imageStates[i]){l.n=1;break}return l.a(2);case 1:return this.imageStates[i]={status:"loading"},l.p=2,o=this.options.size,l.n=3,Sd(i,{size:o.mode==="force"?o.value:void 0,crossOrigin:this.options.crossOrigin||void 0});case 3:s=l.v,this.imageStates[i]=ae({status:"ready",image:s},Ed(s,this.corrector,this.options)),this.scheduleGenerateTexture(),l.n=5;break;case 4:l.p=4,l.v,this.imageStates[i]={status:"error"};case 5:return l.a(2)}},r,this,[[2,4]])}));function e(r){return t.apply(this,arguments)}return e})()},{key:"getAtlas",value:function(){return this.atlas}},{key:"getTextures",value:function(){return this.textures}}])})(zo.EventEmitter);Fe(sa,"NEW_TEXTURE_EVENT","newTexture");var Jc={name:ia("image"),drawingMode:oa(["image","color"],"image"),padding:ra(0),colorAttribute:ia("color"),imageAttribute:ia("image")},Cd={name:"image",drawingMode:"image",padding:0,colorAttribute:"color",imageAttribute:"image"},eh=ae(ae({},kr),{},{drawingMode:"image",shapeFactory:Ye,backgroundLayerFactory:dt,padding:0,colorAttribute:"color",imageAttribute:"image"}),Ld=["textureManager","textureManagerOptions"];function Pd(n){var a=6,t=6;if(n==="image")return a;for(var e=0,r=0;r<n.length;r++)e=(e<<5)-e+n.charCodeAt(r);var i=1+Math.abs(e)%3;return a+i*t}function Fd(n,a){var t=n.name,e=n.drawingMode,r=n.padding,i=Y(1+2*r),o=Math.max(1,a),s="u_atlas_".concat(t),l="layer_".concat(t),u="v_texture_".concat(t),d="v_textureIndex_".concat(t),c="v_color_".concat(t),p=wr(new Array(o)).map(function(g,h){return"if (index == ".concat(h,") texel = texture(").concat(s,"[").concat(h,"], (").concat(u,".xy + coordinateInTexture * ").concat(u,".zw), -1.0);")}).join(`
    else `),v=`else {
      texel = texture(`.concat(s,"[0], (").concat(u,".xy + coordinateInTexture * ").concat(u,`.zw), -1.0);
      noTextureFound = true;
    }`),f=e==="color"?"vec4 ".concat(u,", float ").concat(d,", vec4 ").concat(c):"vec4 ".concat(u,", float ").concat(d),b=`
// Texture atlas uniform - declared here because generator doesn't support sampler2D arrays
uniform sampler2D `.concat(s,"[").concat(o,`];

vec4 `).concat(l,"(").concat(f,`) {
  const float bias = 255.0 / 254.0;
  const float paddingRatio = `).concat(i,`;

  vec4 color = vec4(0.0);

  // Calculate coordinate within the texture
  // The UV is in [-1, 1] range, convert to [0, 1] for texture sampling
  // Note: Camera rotation is handled at the program level (vertex shader)
  vec2 coordinateInTexture = context.uv * vec2(paddingRatio, -paddingRatio) * 0.5 + vec2(0.5, 0.5);
  int index = int(`).concat(d,` + 0.5); // +0.5 to avoid rounding errors

  bool noTextureFound = false;
  vec4 texel = vec4(0.0);

  // No image to display - return transparent
  if (`).concat(u,`.w <= 0.0) {
    // Return transparent when no image
  }
  // Image loaded into the texture
  else {
    `).concat(p,`
    `).concat(v,`

    if (!noTextureFound) {
      `).concat(e==="color"?`// Colorize all visible image pixels with the specified color attribute
      color = mix(vec4(0.0), `.concat(c,", texel.a);"):`// Image mode: render image pixels as-is
      color = texel;`,`

      // Erase pixels "in the padding"
      // context.uv is in [-1, 1], so we check against 1.0 / paddingRatio
      float maxUV = 1.0 / paddingRatio;
      if (abs(context.uv.x) > maxUV || abs(context.uv.y) > maxUV) {
        color = vec4(0.0);
      }
    }
  }

  color.a *= bias;
  return color;
}
`);return b}function ko(n,a){var t=n.name,e=n.drawingMode,r=n.colorAttribute,i=WebGL2RenderingContext,o=i.FLOAT,s=i.UNSIGNED_BYTE,l=Math.max(1,a),u=[],d=[{name:"texture_".concat(t),size:4,type:o,source:"__texture__"},{name:"textureIndex_".concat(t),size:1,type:o,source:"__textureIndex__"}];return e==="color"&&d.push({name:"color_".concat(t),size:4,type:s,normalized:!0,source:r}),{name:t,uniforms:u,attributes:d,glsl:Fd(n,l)}}function Wo(n){var a=ae(ae({},Cd),n||{}),t=a.textureManager,e=a.textureManagerOptions,r=hd(a,Ld),i=r,o=1,s=ko(i,o),l=t??new sa(ae(ae({},kr),e));return ae(ae({},s),{},{lifecycle:function(d){var c=d.gl,p=d.requestShaderRegeneration,v=d.requestRefresh,f=[],b=[],g={},h=Pd(i.name),m=function(){for(;f.length<b.length;){var _=c.createTexture();_&&f.push(_)}for(var T=0;T<b.length;T++)c.activeTexture(c.TEXTURE0+h+T),c.bindTexture(c.TEXTURE_2D,f[T]),c.texImage2D(c.TEXTURE_2D,0,c.RGBA,c.RGBA,c.UNSIGNED_BYTE,b[T]),c.generateMipmap(c.TEXTURE_2D)},x=function(_){var T=_.atlas,R=_.textures,E=R.length!==b.length;g=T,b=R,E&&(o=R.length||1,p()),m(),v()};return{init:function(){l.on(sa.NEW_TEXTURE_EVENT,x),g=l.getAtlas(),b=l.getTextures(),b.length>0&&(f=b.map(function(){return c.createTexture()}),m())},beforeRender:function(){for(var _=0;_<b.length;_++)c.activeTexture(c.TEXTURE0+h+_),c.bindTexture(c.TEXTURE_2D,f[_]);var T=d.getUniformLocation("u_atlas_".concat(i.name));T&&c.uniform1iv(T,wr(new Array(b.length||1)).map(function(R,E){return h+E}))},regenerate:function(){return ko(i,o)},getAttributeData:function(_,T){var R=_[i.imageAttribute];if(T==="__texture__"){var E=R?g[R]:void 0;if(E&&typeof E.textureIndex=="number"){var D=b[E.textureIndex],P=D.width,w=D.height;return[E.x/P,E.y/w,E.size/P,E.size/w]}return[0,0,0,0]}if(T==="__textureIndex__"){var A;typeof R=="string"&&!g[R]&&l.registerImage(R);var F=R?g[R]:void 0;return(A=F?.textureIndex)!==null&&A!==void 0?A:0}return null},kill:function(){l.off(sa.NEW_TEXTURE_EVENT,x);var _=dd(f),T;try{for(_.s();!(T=_.n()).done;){var R=T.value;c.deleteTexture(R)}}catch(E){_.e(E)}finally{_.f()}f=[]}}}})}function zr(n,a){(a==null||a>n.length)&&(a=n.length);for(var t=0,e=Array(a);t<a;t++)e[t]=n[t];return e}function wd(n){if(Array.isArray(n))return zr(n)}function Id(n){if(typeof Symbol<"u"&&n[Symbol.iterator]!=null||n["@@iterator"]!=null)return Array.from(n)}function kd(n,a){if(n){if(typeof n=="string")return zr(n,a);var t={}.toString.call(n).slice(8,-1);return t==="Object"&&n.constructor&&(t=n.constructor.name),t==="Map"||t==="Set"?Array.from(n):t==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)?zr(n,a):void 0}}function zd(){throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function Dt(n){return wd(n)||Id(n)||kd(n)||zd()}function da(n){"@babel/helpers - typeof";return da=typeof Symbol=="function"&&typeof Symbol.iterator=="symbol"?function(a){return typeof a}:function(a){return a&&typeof Symbol=="function"&&a.constructor===Symbol&&a!==Symbol.prototype?"symbol":typeof a},da(n)}function Nr(n){return da(n)==="object"&&n!==null&&"attribute"in n}function Uo(n){return typeof n=="string"}function ua(n){return da(n)==="object"&&n!==null&&"attribute"in n}function Nd(n){var a=n.filter(function(g){return g.fill}).length,t=Y(a||1),e=n.flatMap(function(g,h){if(g.fill)return[];var m=g.size,x=g.mode,y=x==="pixels",_;return ua(m)?_="v_borderSize_".concat(h+1):_=Y(typeof m=="number"?m:0),y?["  float borderSize_".concat(h+1," = ").concat(_," * context.pixelToUV;")]:["  float borderSize_".concat(h+1," = context.shapeHalfSize * ").concat(_,";")]}).join(`
`),r=n.flatMap(function(g,h){return g.fill?[]:["borderSize_".concat(h+1)]}).join(" + "),i=r||"0.0",o=n.flatMap(function(g,h){return g.fill?["  float borderSize_".concat(h+1," = fillBorderSize;")]:[]}).join(`
`),s=n.map(function(g,h){return"  float boundary_".concat(h+1," = boundary_").concat(h," - borderSize_").concat(h+1,";")}).join(`
`),l=n.map(function(g,h){var m=g.color;return Nr(m)?"  vec4 borderColor_".concat(h+1," = v_borderColor_").concat(h+1,";"):"  vec4 borderColor_".concat(h+1," = u_borderColor_").concat(h+1,";")}).join(`
`),u=n.map(function(g,h){return"  borderColor_".concat(h+1,`.a *= bias;
  if (borderSize_`).concat(h+1," <= 2.0 * context.aaWidth) { borderColor_").concat(h+1," = ").concat(h===0?"borderColor_1":"borderColor_".concat(h),"; }")}).join(`
`),d=n.map(function(g,h){return h===0?`if (context.sdf > boundary_1) {
    color = borderColor_1;
  } else `:"if (context.sdf > boundary_".concat(h,` - 2.0 * context.aaWidth) {
    color = mix(borderColor_`).concat(h+1,", borderColor_").concat(h,", (context.sdf - boundary_").concat(h,` + 2.0 * context.aaWidth) / (2.0 * context.aaWidth));
  } else if (context.sdf > boundary_`).concat(h+1,`) {
    color = borderColor_`).concat(h+1,`;
  } else `)}).join(""),c=[].concat(Dt(n.flatMap(function(g,h){var m=g.color;return Nr(m)?["vec4 v_borderColor_".concat(h+1)]:[]})),Dt(n.flatMap(function(g,h){var m=g.size;return ua(m)?["float v_borderSize_".concat(h+1)]:[]}))),p=n.flatMap(function(g,h){var m=g.color;return Uo(m)?["vec4 u_borderColor_".concat(h+1)]:[]}),v=[].concat(Dt(c),Dt(p)).join(", "),f=ua(n[0].size),b=`
vec4 layer_border(`.concat(v,`) {
  const float bias = 255.0 / 254.0;

  // Calculate border sizes (using context.shapeSize and context.pixelSize)
`).concat(e,`
`).concat(f?`
  // Early return if first border size is effectively zero (layer disabled)
  if (borderSize_1 <= context.aaWidth) {
    return vec4(0.0);
  }
`:"",`
  // Calculate fill border size (distribute remaining space)
  // Use inradiusFactor to get actual shape depth from the bounding size
  // For circle/square (inradiusFactor=1.0), this equals shapeSize
  // For triangle (inradiusFactor=0.5), this is half of shapeSize
  float shapeDepth = context.shapeSize * context.inradiusFactor;
  float fillBorderSize = (shapeDepth - (`).concat(i,")) / ").concat(t,`;
`).concat(o,`

  // Calculate cumulative boundaries (from outside to inside in SDF space)
  float boundary_0 = 0.0;  // Shape edge at context.sdf=0
`).concat(s,`

  // Set up colors
`).concat(l,`
`).concat(u,`

  // Select color based on SDF position with antialiasing
  // Note: outer edge AA (context.sdf > 0 transition) is handled by the composed generator's smoothstep
  vec4 color = vec4(0.0);
  `).concat(d,"{ color = borderColor_").concat(n.length,`; }

  return color;
}
`);return b}function Ho(n){var a,t=(a=n?.borders)!==null&&a!==void 0?a:[];if(t.length===0)return{name:"border",uniforms:[],attributes:[],glsl:"vec4 layer_border() { return vec4(0.0); }"};var e=WebGL2RenderingContext,r=e.UNSIGNED_BYTE,i=e.FLOAT,o=t.flatMap(function(l,u){var d=l.color;return Uo(d)?[{name:"u_borderColor_".concat(u+1),type:"vec4",value:ut(d)}]:[]}),s=[].concat(Dt(t.flatMap(function(l,u){var d=l.color;return Nr(d)?[{name:"borderColor_".concat(u+1),size:4,type:r,normalized:!0,source:d.attribute,defaultValue:d.default}]:[]})),Dt(t.flatMap(function(l,u){var d=l.size;return ua(d)?[{name:"borderSize_".concat(u+1),size:1,type:i,source:d.attribute,defaultValue:d.default}]:[]})));return{name:"border",uniforms:o,attributes:s,glsl:Nd(t)}}var ih={borders:Po({size:ra(.1,{variable:!0}),color:Co("#000000",{variable:!0}),mode:oa(["relative","pixels"],"relative"),fill:Lo(!1)})};for(let[n,a]of Object.entries(Er))n!=="default"&&!(n in Ve)&&(Ve[n]=a);Ve.rendering=Rr;Ve.utils=Ar;Ve.layers={layerImage:Wo,layerBorder:Ho};window.Sigma=Ve;})();
//# sourceMappingURL=sigma.bundle.js.map
