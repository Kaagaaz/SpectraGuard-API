// ======================================
// Spectra Guard v4.1 Authentication
// ======================================



// Password hashing

async function hashPassword(password){


    const encoder = new TextEncoder();


    const data = encoder.encode(password);


    const hash = await crypto.subtle.digest(
        "SHA-256",
        data
    );


    return Array.from(
        new Uint8Array(hash)
    )
    .map(
        b => b.toString(16).padStart(2,"0")
    )
    .join("");

}






// ===============================
// Register User
// ===============================


export async function registerUser(
    env,
    username,
    email,
    password
){


    const passwordHash =
        await hashPassword(password);



    const exists =
        await env.DB
        .prepare(
            "SELECT id FROM users WHERE email=?"
        )
        .bind(email)
        .first();



    if(exists){

        return {

            success:false,

            error:"Email already registered"

        };

    }





    const result =
        await env.DB
        .prepare(
        `
        INSERT INTO users
        (
            username,
            email,
            password_hash
        )
        VALUES
        (?,?,?)
        `
        )
        .bind(
            username,
            email,
            passwordHash
        )
        .run();





    return {

        success:true,

        userId:
        result.meta.last_row_id

    };


}









// ===============================
// Login User
// ===============================


export async function loginUser(
    env,
    email,
    password
){



    const passwordHash =
        await hashPassword(password);





    const user =
        await env.DB
        .prepare(
        `
        SELECT *
        FROM users
        WHERE email=?
        AND password_hash=?
        `
        )
        .bind(
            email,
            passwordHash
        )
        .first();






    if(!user){

        return {

            success:false,

            error:"Invalid email or password"

        };

    }






    const token =
        crypto.randomUUID();





    await env.DB
    .prepare(
    `
    INSERT INTO sessions
    (
        user_id,
        token,
        expires_at
    )
    VALUES
    (
        ?,
        ?,
        datetime('now','+7 days')
    )
    `
    )
    .bind(
        user.id,
        token
    )
    .run();






    return {

        success:true,

        token:token,

        username:user.username

    };


}









// ===============================
// Verify Session
// ===============================


export async function verifySession(
    env,
    token
){



    const session =
        await env.DB
        .prepare(
        `
        SELECT *
        FROM sessions
        WHERE token=?
        AND expires_at > datetime('now')
        `
        )
        .bind(token)
        .first();





    if(!session){

        return null;

    }





    return session.user_id;


}
