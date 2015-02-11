/*
    user.js - User model
 */

/*
    Setup User routes to login/logout and ask for a password reminder
 */
angular.module('app').factory('User', function (EspResource) {
    return EspResource.group("user", {}, {
        'check':  { 'method': 'POST', url: '/:server/:controller/check' },
        'forgot': { 'method': 'POST', url: '/:server/:controller/forgot' },
        'login':  { 'method': 'POST', url: '/:server/:controller/login' },
        'logout': { 'method': 'POST', url: '/:server/:controller/logout' },
    });
});
