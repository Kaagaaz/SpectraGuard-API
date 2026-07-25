// ======================================
// Spectra Guard v4.1
// Security Analysis Engine
// Passive Checks Only
// ======================================





// Security header checks

export function checkHeaders(headers){



const issues = [];






if(
!headers.get(
"content-security-policy"
)

){


issues.push({

severity:"Medium",

title:"Missing Content Security Policy (CSP)",

description:
"Website does not provide a CSP header."

});


}









if(
!headers.get(
"strict-transport-security"
)

){


issues.push({

severity:"Low",

title:"HSTS Not Enabled",

description:
"Strict Transport Security header is missing."

});


}









if(
!headers.get(
"x-frame-options"
)

){


issues.push({

severity:"Medium",

title:"Possible Clickjacking Risk",

description:
"X-Frame-Options header was not detected."

});


}









return {


issues


};


}









// Detect possible vulnerable patterns

export function detectVulnerabilities(html){



const vulnerabilities = [];



const source =

html.toLowerCase();









// XSS indicators


if(

source.includes("<script")

&&

source.includes("input")

){


vulnerabilities.push({

severity:"Medium",

title:"Possible XSS Exposure",

description:
"Script and input patterns detected. Proper input validation should be verified."

});


}









// SQL error exposure


const sqlPatterns = [


"sql syntax",

"mysql error",

"database error",

"ora-",

"sqlite error"

];





for(
const pattern of sqlPatterns
){


if(
source.includes(pattern)
){


vulnerabilities.push({

severity:"High",

title:"Possible SQL Error Disclosure",

description:
"Database error patterns detected in page source."

});


break;


}

}









// Authentication related signals


if(

source.includes("login")

&&

!source.includes("csrf")

){


vulnerabilities.push({

severity:"Low",

title:"Authentication Protection Unknown",

description:
"Login functionality detected. CSRF protection could not be verified."

});


}









return vulnerabilities;


}









// Calculate security score


export function calculateScore(data){



let score = 100;


const recommendations = [];







if(!data.https){


score -= 25;


recommendations.push(
"Enable HTTPS on the website."
);


}







score -= data.trackers * 3;



if(data.trackers > 0){


recommendations.push(
"Review third-party trackers."
);


}








score -= data.issues * 5;



if(data.issues > 0){


recommendations.push(
"Improve security headers."
);


}







score -= data.vulnerabilities * 8;



if(data.vulnerabilities > 0){


recommendations.push(
"Review detected security risks."
);


}








if(score < 0){

score = 0;

}







let risk;



if(score >= 85){


risk="Low";


}

else if(score >= 60){


risk="Medium";


}

else if(score >= 35){


risk="High";


}

else{


risk="Critical";


}







return {


score,

risk,

recommendations


};


}
