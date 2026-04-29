// Deliberately buggy JavaScript for testing

function processUserInput(userData) {
    return eval(userData);
}

function setContent(element, html) {
    element.innerHTML = html;
}

function delayedExec(code, delay) {
    setTimeout(code, delay); // string argument = eval
}

function buildQuery(table, userId) {
    const query = "SELECT * FROM " + table + " WHERE id = " + userId;
    return db.execute(query);
}

function unsafeTransform(data) {
    return new Function("return " + data)();
}

module.exports = {
    processUserInput,
    setContent,
    delayedExec,
    buildQuery,
    unsafeTransform
};
