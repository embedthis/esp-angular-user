/*
    user.c - User authentication and management
 */
#include "esp.h"

static void checkAuthenticated() {
    sendResult(httpIsAuthenticated(getConn()));
}

static void createUser() { 
    if (canUser("edit", 1)) {
        setParam("password", mprMakePassword(param("password"), 0, 0));
        sendResult(createRecFromParams("user"));
    }
}

static void getUser() { 
    EdiRec      *rec;
    if ((rec = readRec("user", param("id"))) != 0) {
        /* Don't send the real password back to the user */
        setField(rec, "password", "        ");
        sendRec(rec);
    } else {
        sendResult(0);
    }
}

static void indexUser() {
    sendGrid(readTable("user"));
}

static void initUser() {
    sendRec(createRec("user", 0));
}

static void listUsers() {
    EdiGrid     *users;
    int         r;

    users = readTable("user");
    for (r = 0; r < users->nrecords; r++) {
        setField(users->records[r], "password", 0);
    }
    sendGrid(users);
}

static void removeUser() { 
    if (canUser("edit", 1)) {
        sendResult(removeRec("user", param("id")));
    }
}

static void updateUser() {
    EdiRec  *rec;
    cchar   *password;
    if (canUser("edit", 1)) {
        password = strim(param("password"), " ", 0);
        if (smatch(password, "") && (rec = readRec("user", param("id"))) != 0) {
            password = getField(rec, "password");
            setParam("password", password);
        } else {
            setParam("password", mprMakePassword(password, 0, 0));
        }
        if (!updateRecFromParams("user") || ediSave(getDatabase()) < 0) {
            sendResult(0);
        } else {
            sendResult(1);
        }
    }
}

static void forgotPassword() {
    EdiRec  *user;
    cchar   *msg, *name, *to;

    name = param("recover");
    if ((user = readRecWhere("user", "username", "==", name)) == 0) {
        if ((user = readRecWhere("user", "email", "==", name)) == 0) {
            /* Security delay */
            mprSleep(2500);
            sendResult(feedback("error", "Unknown user."));
            return;
        }
    }
    to = getField(user, "email");
    msg = sfmt("Password Reset\nPlease use this new temporary password %s\nLogin at %s\n",
        "temp", sjoin(httpLink(getConn(), "~"), "/user/login", NULL));
    if (espEmail(getConn(), to, "mob@emobrien.com", "Reset Password", 0, 0, msg, 0) < 0) {
        sendResult(feedback("error", "Cannot send password reset email."));
    } else {
        sendResult(feedback("inform", "Password reset details sent."));
    }
}

static void loginUser() {
    bool        remember = smatch(param("remember"), "true");
    HttpConn    *conn = getConn();

    if (httpLogin(conn, param("username"), param("password"))) {
        render("{\"error\": 0, \"user\": {\"name\": \"%s\", \"abilities\": %s, \"remember\": %s}}", conn->username,
            mprSerialize(conn->user->abilities, MPR_JSON_QUOTES), remember ? "true" : "false");
    } else {
        sendResult(feedback("error", "Invalid Login"));
    }       
}

static void logoutUser() {                                                                             
    httpLogout(getConn());
    espClearCurrentSession(getConn());
    sendResult(1);
}

/*
    Verify user credentials from database password.
    Callback from httpLogin to verify the username/password
 */
static bool verifyUser(HttpConn *conn, cchar *username, cchar *password)
{
    HttpAuth    *auth;
    HttpUser    *user;
    HttpRx      *rx;
    EdiRec      *urec;

    rx = conn->rx;
    auth = rx->route->auth;

    if ((urec = readRecWhere("user", "username", "==", username)) == 0) {
        httpTrace(conn, "auth.login.error", "error", "msg=\"Cannot verify user\"", username=%s", username);
        return 0;
    }
    if (username && *username && smatch(username, auth->username)) {
        /* Autologin */
        httpTrace(conn, "auth.login.authenticated", "context", "msg=\"Auto login\"", username=%s", username);

    } else if (!mprCheckPassword(password, getField(urec, "password"))) {
        httpTrace(conn, "auth.login.error", "error", "msg=\"Password failed to authenticate\", username=%s", username);
        mprSleep(500);
        return 0;
    }
    /*
        Restrict to a single simultaneous login
     */
    if (espTestConfig(rx->route, "app.http.auth.login.single", "true")) {
        if (!espIsCurrentSession(conn)) {
            feedback("error", "Another user still logged in");
            httpTrace(conn, "auth.login.error", "error", "msg=\"Too many simultaneous users\"");
            return 0;
        }
        espSetCurrentSession(conn);
    }
    if ((user = httpLookupUser(auth, username)) == 0) {
        user = httpAddUser(auth, username, 0, ediGetFieldValue(urec, "roles"));
    }
    httpSetConnUser(conn, user);
    httpTrace(conn, "auth.login.authenticated", "context", "msg=\"User authenticated\", username=%s", username);
    return 1;
}

#if KEEP
/*
    Define this code if you wish to require a login for all requests. 
    Enable espDefineBase(, commonController) below
 */
static void commonController(HttpConn *conn)
{
    HttpRoute   *route;
    cchar       *autoLogin, *loginRequired, *uri, *stem;

    if (!httpLoggedIn(conn)) {
        uri = getUri();
        route = conn->rx->route;
        if (!route->serverPrefix || sstarts(uri, route->serverPrefix)) {
            stem = (route->serverPrefix) ?  &uri[slen(route->serverPrefix)] : uri;
            if (smatch(stem, "/user/login") || smatch(stem, "/user/logout") || smatch(stem, "/user/forgot")) {
                return;
            }
            loginRequired = espGetConfig(route, "app.http.auth.require.users", 0);
            autoLogin = espGetConfig(route, "app.http.auth.login.name", 0);
            if (loginRequired && !(autoLogin && *autoLogin)) {
                httpError(conn, HTTP_CODE_UNAUTHORIZED, "Access Denied. Login required");
            }
        }
    }
}
#endif

ESP_EXPORT int esp_controller_${APP}_user(HttpRoute *route, MprModule *module) 
{
    Edi     *edi;

    httpSetAuthVerify(route->auth, verifyUser);

#if KEEP
    espDefineBase(route, commonController);
#endif
    espDefineAction(route, "user/create", createUser);
    espDefineAction(route, "user/get", getUser);
    espDefineAction(route, "user/list", listUsers);
    espDefineAction(route, "user/index", indexUser);
    espDefineAction(route, "user/init", initUser);

    espDefineAction(route, "user/remove", removeUser);
    espDefineAction(route, "user/update", updateUser);

    espDefineAction(route, "user/check", checkAuthenticated);
    espDefineAction(route, "user/forgot", forgotPassword);
    espDefineAction(route, "user/login", loginUser);
    espDefineAction(route, "user/logout", logoutUser);

    edi = espGetRouteDatabase(route);
    ediAddValidation(edi, "present", "user", "username", 0);
    ediAddValidation(edi, "unique", "user", "username", 0);
    ediAddValidation(edi, "present", "user", "email", 0);
    ediAddValidation(edi, "format", "user", "email", ".*@.*");
    ediAddValidation(edi, "unique", "user", "email", 0);
    ediAddValidation(edi, "present", "user", "roles", 0);
    return 0;
}
