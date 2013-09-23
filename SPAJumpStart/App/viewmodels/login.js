define(['durandal/app', 'services/datacontext', 'durandal/plugins/router'],
    function (app, datacontext, router) {

    var register = function () { router.replaceLocation('#/register'); };

    var login = function () {
        var credentials = { UserName: vm.UserName.peek(), Password: vm.Password.peek(), RememberMe: vm.RememberMe.peek() };
        result(datacontext.login(credentials));

        function result(res) {
            if (res.success) {
                router.replaceLocation('#/sessions');
            } else {
                vm.Message(res.message);
            }
        };
    };

        

    var vm = {
        
        title: 'Login',
        login: login,
        register: register,
        UserName: ko.observable(),
        Password: ko.observable(),
        RememberMe: ko.observable(),
        Message: ko.observable()
    };
    
    return vm;
});