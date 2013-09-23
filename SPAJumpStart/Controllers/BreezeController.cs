using System;
using System.Collections.Generic;
using System.Data.Objects;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Transactions;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Security;
//using AuthApplication.Controllers;
using CodeCamper.Filters;
using CodeCamper.Models;
using Breeze.WebApi;
using DotNetOpenAuth.AspNet;
using Microsoft.Web.WebPages.OAuth;
using Newtonsoft.Json.Linq;
using WebMatrix.WebData;

namespace CodeCamper.Controllers
{
    //MVC-AUTHENTICATION CODE
    // added 'System.Web.Http.Authorize' attribute to prevent unauthorized use of controller
    // Metadata and Lookups (information for dropdowns in Add Session) have 'AllowAnonymous' as this data is used
    // initializing the SPA and is not 'sensitive' data.
    // the MVC.Authorize attribute does not work in MVC API apps, thus we use the Http namespace version
    [System.Web.Http.Authorize]
    [BreezeController()]
    public class BreezeController : ApiController
    {
        readonly EFContextProvider<CodeCamperDbContext>  _contextProvider =
            new EFContextProvider<CodeCamperDbContext>();

        [System.Web.Http.AllowAnonymous]
        [System.Web.Http.HttpGet]
        public string Metadata()
        {
            return _contextProvider.Metadata();
        }

        [System.Web.Http.HttpPost]
        public SaveResult SaveChanges(JObject saveBundle)
        {
            return _contextProvider.SaveChanges(saveBundle);
        }

        [System.Web.Http.AllowAnonymous]
        [System.Web.Http.HttpGet]
        public object Lookups()
        {
            var rooms =  _contextProvider.Context.Rooms;
            var tracks =  _contextProvider.Context.Tracks;
            var timeslots =  _contextProvider.Context.TimeSlots;
            return new {rooms, tracks, timeslots};
        }

        [System.Web.Http.HttpGet]
        public IQueryable<Session> Sessions()
        {
            return _contextProvider.Context.Sessions;
        }

        [System.Web.Http.HttpGet]
        public IQueryable<Person> Persons()
        {
            return _contextProvider.Context.Persons;
        }

        [System.Web.Http.HttpGet]
        public IQueryable<Person> Speakers()
        {
            return _contextProvider.Context.Persons
                .Where(p => p.SpeakerSessions.Any());
        }

   }
}