// ======================================
// Spectra Guard v4.1 Scanner Engine
// Passive Website Analysis
// ======================================


import {

checkHeaders,
detectVulnerablePatterns,
calculateRisk

} from "./security.js";






export async function scanWebsite(url){



    let target;



    try{


        target = new URL(url);


    }

    catch{


        return {

            found:false,

            error:"Invalid website URL"

        };

    }








    try{


        const response = await fetch(
            target.href,
            {

                method:"GET",

                redirect:"follow",

                headers:{

                    "User-Agent":
                    "SpectraGuard Security Scanner"

                }

            }
        );






        const html =
        await response.text();






        const headers =
        response.headers;







        // HTTPS


        const https =
        target.protocol === "https:";








        // Cookies


        const cookies =
        headers.get(
            "set-cookie"
        )
        ? 1
        : 0;








        // Tracker detection


        let trackers = 0;



        const trackerList = [


            "google-analytics",


            "googletagmanager",


            "facebook.net",


            "doubleclick",


            "hotjar"


        ];





        trackerList.forEach(
            tracker=>{


                if(
                    html.includes(tracker)
                ){

                    trackers++;

                }


            }

        );









        // Security checks


        const headerResult =
        checkHeaders(headers);





        const vulnerabilities =
        detectVulnerablePatterns(html);








        const issues =
        [

            ...headerResult.issues

        ];







        const allVulnerabilities =
        [

            ...vulnerabilities

        ];









        // Score system


        let score = 100;





        if(!https){

            score -= 25;

        }



        score -=
        issues.length * 5;



        score -=
        allVulnerabilities.length * 3;



        score -=
        trackers * 2;








        if(score < 0){

            score = 0;

        }








        return {


            found:true,


            website:
            target.hostname,



            https,



            cookies,



            trackers,



            technologies:
            [],




            vulnerabilities:
            allVulnerabilities,




            issues,




            recommendations:
            headerResult.recommendations,




            score,



            risk:
            calculateRisk(score)



        };





    }

    catch(error){


        return {


            found:false,


            error:
            "Website could not be scanned"



        };


    }



}
