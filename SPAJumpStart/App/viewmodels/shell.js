define(['durandal/system',
        'services/logger',
        'durandal/plugins/router',
        'durandal/app',
        'config',
        'services/datacontext'],
    function (system, logger, router, app, config, datacontext) {

        var adminRoutes = ko.computed(function() {
            return router.allRoutes().filter(function(r) {
                return r.settings.admin;
            });
        });
        
        //MVC-AUTHENTICATION CODE
        //Added to provide Acount Registration/Login access in the Nav menu
        var accountRoutes = ko.computed(function () {
            return router.allRoutes().filter(function (r) {
                return r.settings.account;
            });
        });

        var shell = {
            activate: activate,
            addSession: addSession,
            adminRoutes: adminRoutes,
            //MVC-AUTHENTICATION CODE
            accountRoutes: accountRoutes, //This defines accountRoutes in the shell, to get the links for the account drop down
            router: router
        };
        return shell;

        function activate() {
            app.title = config.appTitle;
            return datacontext.primeData()
                .then(boot)
                .fail(failedInitialization);
        }
        
        //MVC-AUTHENTICATION CODE
        //Modified BOOT function to adjust behavior based on whether user is Authenticated
        function boot() {
            logger.log('CodeCamper JumpStart Loaded!', null, system.getModuleId(shell), true);
            //MVC-AUTHENTICATION CODE
            //Map Routes- NoAuth first, then add authorized routes if authenticated
            router.map(config.routesNoAuth);
            var start = config.loginModule;
            //MVC-AUTHENTICATION CODE
            //Change the start module to Sessions if authenticated, and complete postLoginConfig from datacontext
            if (datacontext.isAuthorized()) {
                datacontext.postLoginConfig();
                start = config.loginModule;
            }
            return router.activate(start);
        }

        function addSession(item) {
            router.navigateTo(item.hash);
        }


        function failedInitialization(error) {
            var msg = 'App initialization failed: ' + error.message;
            logger.logError(msg, error, system.getModuleId(shell), true);
        }
    }
);