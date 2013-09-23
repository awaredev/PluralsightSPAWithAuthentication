define(function () {
    toastr.options.timeOut = 4000;
    toastr.options.positionClass = 'toast-bottom-right';

    var imageSettings = {
        imageBasePath: '../content/images/photos/',
        unknownPersonImageSource: 'unknown_person.jpg'
    };

    var remoteServiceName = 'breeze/Breeze';

    var appTitle = 'CCJS';

    //MVC-AUTHENTICATION CODE
    //Route objects for Account- these are removed upon Login
    var loginNav = {
        url: 'login',
        moduleId: 'viewmodels/login',
        name: 'Login',
        visible: false,
        caption: 'Login',
        settings: { account: true, caption: '<i class="icon-plus"></i> Login' }
    };

    var registerNav = {
        url: 'register',
        moduleId: 'viewmodels/register',
        name: 'Register',
        visible: false,
        caption: 'Register',
        settings: { account: true, caption: '<i class="icon-plus"></i> Register' }
    };
    //MVC-AUTHENTICATION CODE
    //These Routes are done once authenticated 
    var routes = [{
        url: 'sessions',
        moduleId: 'viewmodels/sessions',
        name: 'Sessions',
        visible: true,
        caption: 'Sessions',
        settings: { caption: '<i class="icon-book"></i> Sessions' }
        }, {
        url: 'speakers',
        moduleId: 'viewmodels/speakers',
        name: 'Speakers',
        caption: 'Speakers',
        visible: true,
        settings: { caption: '<i class="icon-user"></i> Speakers' }
        }, {
        url: 'sessiondetail/:id',
        moduleId: 'viewmodels/sessiondetail',
        name: 'Edit Session',
        caption: 'Edit Session',
        visible: false
    }, {
        url: 'sessionadd',
        moduleId: 'viewmodels/sessionadd',
        name: 'Add Session',
        visible: false,
        caption: 'Add Session',
        settings: { admin: true, caption: '<i class="icon-plus"></i> Add Session' }
    }];
    //MVC-AUTHENTICATION CODE
    //Alternate Routes for non authenticated users
    //Routes are all present as Router needs them initialised at first as initialising later will not allow navigation- but they are invisible
    var routesNoAuth = [{
        url: 'sessions',
        moduleId: 'viewmodels/sessions',
        name: 'Sessions',
        visible: false,
        
    }, {
        url: 'speakers',
        moduleId: 'viewmodels/speakers',
        name: 'Speakers',
        visible: false,
    }, {
        url: 'sessiondetail/:id',
        moduleId: 'viewmodels/sessiondetail',
        name: 'Edit Session',
        caption: 'Edit Session',
        visible: false
    }, {
        url: 'sessionadd',
        moduleId: 'viewmodels/sessionadd',
        name: 'Add Session',
        visible: false,
    },
        //MVC-AUTHENTICATION CODE
    //These are the drop down options for Account
        //loginNav and registerNav are variables to allow easy removal at login
        loginNav, registerNav,
        //Invisible logout
        {
            url: 'logout',
            moduleId: 'viewmodels/logout',
            name: 'Logout',
            visible: false,
        }
    ];

    

    var startModule = 'sessions';
    //MVC-AUTHENTICATION CODE
    //Added Login Module to force Login
    var loginModule = 'login';

    return {
        appTitle: appTitle,
        debugEnabled: ko.observable(true),
        imageSettings: imageSettings,
        remoteServiceName: remoteServiceName,
        routes: routes,
        //Non AUthenticated Routes
        routesNoAuth: routesNoAuth,
        startModule: startModule,
        //Added Login Module to force Login
        loginModule: loginModule,
        loginNav: loginNav,
        registerNav: registerNav
    };
});