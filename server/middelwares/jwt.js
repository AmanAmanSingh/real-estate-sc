const jwt = require("jsonwebtoken");

const Authentication = ((req, res, next) => {

    const Token = req.headers.authorization;
    jwt.verify(Token, process.env.SECRET_KEY, async (err, decode) => {
        if (err) {
            return res.status(400).json({
                message: "Token expired"
            })
        }
        req.user = decode.data;
        next();
    })

})
module.exports = Authentication;