// ======================================
// Spectra Guard API v4.1
// Public Scanner API
// ======================================


import { scanWebsite } from "./scanner.js";





export default {


async fetch(request){



const cors = {

"Access-Control-Allow-Origin":"*",

"Access-Control-Allow-Headers":"Content-Type",

"Access-Control-Allow-Methods":"GET, OPTIONS"

};





if(request.method==="OPTIONS"){


return new Response(null,{
headers:cors
});


}







const url =
new URL(request.url);



const path =
url.pathname;









// API status


if(path === "/"){


return Response.json({

status:"online",

service:"Spectra Guard API",

version:"4.1"


},{
headers:cors
});


}









// Website scanner


if(
path === "/scan" &&
request.method === "GET"
){



const target =

url.searchParams.get("url");





if(!target){


return Response.json({

found:false,

error:"No website URL provided"


},{
status:400,
headers:cors
});


}







const result =

await scanWebsite(target);






return Response.json(

result,

{

headers:cors

}

);



}








return Response.json({

error:"Route not found"


},{

status:404,

headers:cors

});





}


};
