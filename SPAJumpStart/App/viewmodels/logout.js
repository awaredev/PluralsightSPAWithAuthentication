define(['durandal/app', 'services/datacontext', 'durandal/plugins/router'],
    function (app, datacontext, router) {

    var register = function () { router.replaceLocation('#/register'); };

    var activate = function () {
        result(datacontext.logout());

        function result(res) {
            if (res.success) {
                router.replaceLocation('');
            } else {
                vm.Message(res.message);
            }
        };
    };

        

    var vm = {
        
        title: 'Logout',
        activate: activate,
        Message: ko.observable()
    };
    
    return vm;
});