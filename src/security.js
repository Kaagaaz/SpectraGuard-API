// ======================================
// Spectra Guard v4.1 Security Engine
// Passive Security Checks
// ======================================



// Check security headers

export function checkHeaders(headers){


    const issues = [];



    const recommendations = [];





    if(!headers.get("content-security-policy")){


        issues.push({

            severity:"Medium",

            title:"Missing Content Security Policy",

            description:
            "CSP header is not present."

        });



        recommendations.push(
            "Add a Content Security Policy (CSP) header."
        );


    }






    if(!headers.get("x-frame-options")){


        issues.push({

            severity:"Medium",

            title:"Missing X-Frame-Options",

            description:
            "Clickjacking protection header not detected."

        });



        recommendations.push(
            "Enable X-Frame-Options or frame-ancestors CSP."
        );


    }







    if(!headers.get("strict-transport-security")){


        issues.push({

            severity:"Low",

            title:"HSTS Not Enabled",

            description:
            "HTTP Strict Transport Security is missing."

        });



        recommendations.push(
            "Enable HSTS for HTTPS protection."
        );


    }





    return {

        issues,

        recommendations

    };

}









// Detect suspicious patterns in HTML


export function detectVulnerablePatterns(html){



    const vulnerabilities = [];





    // Possible exposed debug information


    if(
        html.includes("debug") ||
        html.includes("console.log")
    ){


        vulnerabilities.push({

            severity:"Low",

            title:"Possible Debug Code Exposure",

            description:
            "Debug-related code detected in page source."

        });


    }







    // Possible reflected input areas


    if(
        html.includes("<form") &&
        html.includes("input")
    ){


        vulnerabilities.push({

            severity:"Info",

            title:"Input Forms Detected",

            description:
            "Forms exist and should use proper validation."

        });


    }







    // Technology disclosure


    if(
        html.includes("wp-content") ||
        html.includes("wordpress")
    ){


        vulnerabilities.push({

            severity:"Info",

            title:"Technology Information Exposed",

            description:
            "Website technology signatures detected."

        });


    }






    return vulnerabilities;


}









// Basic risk calculation


export function calculateRisk(
    score
){


    if(score >= 85){

        return "Low";

    }


    if(score >= 60){

        return "Medium";

    }


    if(score >= 35){

        return "High";

    }


    return "Critical";


}
