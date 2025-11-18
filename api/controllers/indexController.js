
exports.index = async (req, res) => {
    try {
        res.render("index", {title: "Express"});
    } catch (err) {
        res.status(500).send(err);
    }
}


module.exports = exports;