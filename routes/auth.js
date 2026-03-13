var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator, ChangePasswordValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let {checkLogin} = require('../utils/authHandler')
let fs = require('fs')
let path = require('path')
let privateKey = fs.readFileSync(path.join(__dirname, '../privateKey.key'), 'utf8')

/* GET home page. */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '30d'
            })
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});

router.post('/change-password', checkLogin, ChangePasswordValidator, handleResultValidator, async function (req, res, next) {
    try {
        let { oldPassword, newPassword } = req.body;
        let getUser = await userController.FindById(req.user._id);

        if (!getUser) {
            return res.status(404).json({ message: "nguoi dung khong ton tai" });
        }

        if (oldPassword === newPassword) {
            return res.status(400).json({ message: "mat khau moi khong duoc trung voi mat khau cu" });
        }

        if (bcrypt.compareSync(oldPassword, getUser.password)) {
            getUser.password = newPassword;
            await getUser.save();
            res.json({ message: "doi mat khau thanh cong" });
        } else {
            res.status(403).json({ message: "mat khau cu khong dung" });
        }
    } catch (error) {
        next(error);
    }
});

router.get('/me',checkLogin,function(req,res,next){
    res.send(req.user)
})


module.exports = router;
