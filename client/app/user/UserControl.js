/*
    UserControl.js - User Controller

    This controller manages user login/logout and admin editing of user configuration.
 */
 
'use strict';

angular.module('app').controller('UserControl', function (Esp, User, $rootScope, $route, $scope, $location, $modal, $routeParams, $timeout, $window) {
    angular.extend($scope, $routeParams);

    $scope.user = {};
    $scope.roles = { administrator: false, user: false };

    if (Esp.user || !Esp.config.auth.login.url) {
        if ($scope.id) {
            User.get({id: $scope.id}, $scope, function(response) {
                var roles = response.user.roles.split(",");
                angular.forEach(roles, function(value, key) {
                    value = value.trim();
                    $scope.roles[value] = true;
                });
            });
        } else if ($location.path().indexOf('/user/list') == 0) {
            User.list(null, $scope, {users: "data"});

        } else if ($location.path() == "/user/") {
            User.init(null, $scope);
        }
    } else {
        var loc = $location.path();
        if ($location.path().indexOf('/user/login') != 0) {
            $rootScope.feedback = { warning: "Insufficient Privilege to view users" };
        }
    }

    $scope.save = function() {
        var roles = "";
        angular.forEach($scope.roles, function(value, key) {
            if (value != false) {
                roles += key + ", ";
            }
        });
        $scope.user.roles = roles.replace(/[, ]*$/, '');
        User.update($scope.user, $scope, function(response) {
            if (!response.error) {
                $location.path('/user/list');
            }
        });
    };

    $scope.login = function(dialog) {
        User.login($scope.user, function(response, fn) {
            if (response.error) {
                Esp.logout();
                $location.path("/");
            } else {
                Esp.login(response.user);
                dialog.dismiss();
                if (Esp.referrer && Esp.referrer.indexOf("user/login") < 0) {
                    $window.location.href = Esp.referrer;
                    Esp.referrer = null;
                } else {
                    $location.path("/");
                }
            }
        }, function(response, fn) {
            console.log(response);
        });
    };

    $scope.logout = function() {
        if (Esp.user) {
            User.logout({}, function() {
                $rootScope.feedback = { inform: "Logged Out" };
                $location.path("/");
                $route.reload();
            });
            Esp.logout();
        } else {
            $rootScope.feedback = { inform: "Logged Out" };
            $location.path("/");
        }
    };

    $scope.forgot = function() {
        var esp = angular.module('esp');
        var confirm = $modal.open({
            scope: $scope,
            templateUrl: esp.url('/app/user/user-forgot.html'),
        });
        confirm.result.then(function(result) {
            if (result) {
                User.forgot($scope.user, function(response, fn) {
                    $location.path("/");
                });
            }
        });
    };

    $scope.remove = function() {
        $modal.open({
            scope: $scope,
            template: '<esp-confirm header="Are you sure?" body="Do you want to remove user: {{user.username}}?" ok="Delete User">',
        }).result.then(function(result) {
            if (result) {
                User.remove({id: $scope.user.id}, function(response) {
                    $location.path("/user/list");
                });
            }
        });
    };
    $scope.authname = function () {
        return (Esp.user && Esp.user.name) || 'guest';
    }
});

/*
    Routes for User
 */
angular.module('app').config(function($routeProvider) {
    var esp = angular.module('esp');
    var Default = {
        controller: 'UserControl',
        resolve: { action: esp.checkAuth },
    };
    $routeProvider.when('/user/list',   angular.extend({}, Default, {templateUrl: esp.url('/app/user/user-list.html')}));
    $routeProvider.when('/user/login',  angular.extend({}, Default, {templateUrl: esp.url('/app/user/user-login.html')}));
    $routeProvider.when('/user/logout', angular.extend({}, Default, {template: '<p ng-init="logout()"> </p>'}));
    $routeProvider.when('/user/:id', angular.extend({}, Default, {
        templateUrl: esp.url('/app/user/user-edit.html'),
        abilities: { 'edit': true, 'view': true },
    }));
});
