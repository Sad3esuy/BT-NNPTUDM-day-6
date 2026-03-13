let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
let fs = require('fs')
let path = require('path')
let publicKey = fs.readFileSync(path.join(__dirname, '../publicKey.key'), 'utf8')

module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            return res.status(403).send("ban chua dang nhap");
        }
        token = token.split(" ")[1];
        try {//private - public
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            let user = await userController.FindById(result.id)
            if (!user) {
                return res.status(403).send("ban chua dang nhap");
            } else {
                req.user = user;
                next()
            }
        } catch (error) {
            console.log(error)
            return res.status(403).send("ban chua dang nhap");
        }

    }
}