// ======================================
// Spectra Guard v4.1
// Website Scanner Engine
// Passive Analysis Only
// ======================================


import {

checkHeaders,
detectVulnerabilities,
calculateScore

} from "./security.js";








export async function scanWebsite(targetUrl){



let website;



// Validate URL


try{


website = new URL(targetUrl);



}

catch{


return {

found:false,

error:"Website not found"

};


}






// Only allow http/https


if(

website.protocol !== "https:" &&

website.protocol !== "http:"

){


return {

found:false,

error:"Invalid website protocol"

};


}







try{



const response = await fetch(

website.href,

{

method:"GET",

redirect:"follow",

headers:{

"User-Agent":

"SpectraGuard Security Scanner"

}

}

);






if(!response.ok){


return {

found:false,

error:"Website unavailable",

status:response.status

};


}







const html = await response.text();


const headers = response.headers;









// HTTPS check


const https =

website.protocol === "https:";









// Cookie detection


const cookieHeader =

headers.get("set-cookie");



const cookies =

cookieHeader ? 1 : 0;









// Tracker detection


const trackersList = [


"google-analytics",

"googletagmanager",

"doubleclick",

"facebook.net",

"hotjar",

"clarity.ms"

];





let trackers = 0;



for(
const tracker of trackersList
){


if(

html.toLowerCase()

.includes(

tracker

)

){


trackers++;

}


}









// Security analysis


const securityResult =

checkHeaders(headers);






const vulnerabilities =

detectVulnerabilities(html);









const scoreData =

calculateScore({

https,

trackers,

issues:

securityResult.issues.length,

vulnerabilities:

vulnerabilities.length

});









return {


found:true,


website:

website.hostname,



https,



cookies,



trackers,



score:

scoreData.score,



risk:

scoreData.risk,



issues:

securityResult.issues,



vulnerabilities,



recommendations:

scoreData.recommendations



};







}

catch(error){


return {


found:false,

error:"Unable to scan website"


};


}


}
