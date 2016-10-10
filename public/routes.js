/**
 * Created by irkalla on 28.09.16.
 */
angular.module('App', ['ngRoute']).config(function($routeProvider) {
    $routeProvider

    // route for the home page
        .when('/', {
            templateUrl : 'views/crypto.html',
            controller  : 'cryptoController'
        });


});