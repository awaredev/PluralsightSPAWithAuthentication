define(['durandal/app', 'services/datacontext', 'durandal/plugins/router'],
   function (app, datacontext, router){

    register = function () {
        var userRegistration = { UserName: vm.UserName.peek(), Password: vm.Password.peek(), ConfirmPassword: vm.ConfirmPassword.peek() };
        result(datacontext.register(userRegistration));
        
        function result(res) {
            if (res.success) {
                router.replaceLocation('#/sessions');
            } else {
                vm.Message(res.message);
            }
        };

    };

    var vm = {

        title: 'Register',
        register: register,
        UserName: ko.observable(),
        Password: ko.observable(),
        ConfirmPassword: ko.observable(),
        Message: ko.observable()
    };

    return vm;
});