const mongoose = require("mongoose");

const basicInfoSchema = new mongoose.Schema({
    property: {
        type: String,
        enum: ["plot", "house", "flat"],
        required: true
    },
    negotable: {
        type: String,
        enum: ["yes", "no"],
        default: "yes"
    },
    price: {
        type: Number,
    },
    ownership: {
        type: String,
        enum: ["dealer", "self"],
        default: "self"
    },
    propertyAge: {
        type: Number,
    },
    propertyApproved: {
        type: String,
        enum: ["yes", "no"],
        default: "yes"
    },
    propertyDescription: {
        type: String,
    },
    bankLoan: {
        type: String,
        enum: ["yes", "no"],
        default: "no"
    }

}, { timestamps: true });

module.exports = mongoose.model("basicinfos", basicInfoSchema)