const mongoose = require('mongoose');

const connection = () => {
    mongoose.set('strictQuery', false);
    mongoose.connect(process.env.DATABASE_URI, { useNewUrlParser: true, useUnifiedTopology: true },
        () => {
            console.log("mongo connected sucessfully")
        }, (err) => {
            console.log(err.message)
        })
}

module.exports = connection;
