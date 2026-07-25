// ======================================
// Spectra Guard v4.1 Main API
// Cloudflare Worker
// ======================================


import {

registerUser,
loginUser,
verifySession

} from "./auth.js";



import {

scanWebsite

} from "./scanner.js";







export default {


async fetch(request, env){



const cors = {


"Access-Control-Allow-Origin":"*",


"Access-Control-Allow-Headers":

"Content-Type, Authorization",


"Access-Control-Allow-Methods":

"GET, POST, OPTIONS"


};







if(request.method==="OPTIONS"){


return new Response(

null,

{

headers:cors

}

);


}







const url =
new URL(request.url);



const path =
url.pathname;








// =================================
// TEST
// =================================


if(path==="/"){


return Response.json(

{

status:"online",

message:
"Spectra Guard API v4.1"

},

{

headers:cors

}

);


}









// =================================
// REGISTER
// =================================


if(
path==="/register"
&&
request.method==="POST"
){



const body =
await request.json();





const result =

await registerUser(

env,

body.username,

body.email,

body.password

);





return Response.json(

result,

{

headers:cors

}

);



}









// =================================
// LOGIN
// =================================


if(
path==="/login"
&&
request.method==="POST"
){



const body =
await request.json();





const result =

await loginUser(

env,

body.email,

body.password

);





return Response.json(

result,

{

headers:cors

}

);



}









// =================================
// WEBSITE SCAN
// =================================


if(
path==="/scan"
&&
request.method==="GET"
){



const website =

url.searchParams.get(
"url"
);





if(!website){


return Response.json(

{

error:
"Missing URL"

},

{

status:400,

headers:cors

}

);


}







const result =

await scanWebsite(

website

);






return Response.json(

result,

{

headers:cors

}

);



}









// =================================
// SAVE SCAN
// =================================


if(
path==="/save-scan"
&&
request.method==="POST"
){



const auth =

request.headers.get(
"Authorization"
);





if(!auth){


return Response.json(

{

error:
"Login required"

},

{

status:401,

headers:cors

}

);


}







const token =

auth.replace(
"Bearer ",
""
);






const userId =

await verifySession(

env,

token

);







if(!userId){


return Response.json(

{

error:
"Invalid session"

},

{

status:401,

headers:cors

}

);


}








const data =

await request.json();








let website =

await env.DB

.prepare(

`

SELECT id

FROM websites

WHERE user_id=?

AND url=?

`

)

.bind(

userId,

data.website

)

.first();







if(!website){



const created =

await env.DB

.prepare(

`

INSERT INTO websites

(user_id,url)

VALUES(?,?)

`

)

.bind(

userId,

data.website

)

.run();





website = {


id:
created.meta.last_row_id


};



}









await env.DB

.prepare(

`

INSERT INTO scans

(

website_id,

score,

risk,

https,

cookies,

trackers,

technologies,

vulnerabilities,

issues,

recommendations

)

VALUES

(?,?,?,?,?,?,?,?,?,?)

`

)

.bind(

website.id,

data.score,

data.risk,

data.https ? 1 : 0,

data.cookies,

data.trackers,

JSON.stringify(
data.technologies
),

JSON.stringify(
data.vulnerabilities
),

JSON.stringify(
data.issues
),

JSON.stringify(
data.recommendations
)

)

.run();







return Response.json(

{

success:true

},

{

headers:cors

}

);



}









// =================================
// SCAN HISTORY
// =================================


if(
path==="/history"
&&
request.method==="GET"
){



const auth =

request.headers.get(
"Authorization"
);





const token =

auth?.replace(
"Bearer ",
""
);






const userId =

await verifySession(

env,

token

);






if(!userId){


return Response.json(

{

error:
"Unauthorized"

},

{

status:401,

headers:cors

}

);


}








const history =

await env.DB

.prepare(

`

SELECT

websites.url,

scans.*

FROM scans

JOIN websites

ON scans.website_id = websites.id

WHERE websites.user_id=?

ORDER BY scans.created_at DESC

`

)

.bind(userId)

.all();








return Response.json(

history.results,

{

headers:cors

}

);



}









return Response.json(

{

error:
"Route not found"

},

{

status:404,

headers:cors

}

);



}

};
