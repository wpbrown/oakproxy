using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Web.Mvc;

namespace testapp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Api()
        {
            var user = (WindowsIdentity)User.Identity;

            var localData = new {
                Message = "Hello",
                user.Name,
                user.IsAuthenticated,
                user.AuthenticationType,
                ImpersonationLevel = user.ImpersonationLevel.ToString()
            };

            JObject remoteData = null;

            try
            {
                string remoteDataString;

                using (user.Impersonate())
                {
                    var request = WebRequest.Create("http://testapp/api");
                    request.UseDefaultCredentials = true;
                    request.ImpersonationLevel = TokenImpersonationLevel.Impersonation;
                    var response = request.GetResponse();
                    Stream dataStream = response.GetResponseStream();
                    var reader = new StreamReader(dataStream);
                    remoteDataString = reader.ReadToEnd();
                    reader.Close();
                    dataStream.Close();
                    response.Close();
                }

                remoteData = JObject.Parse(remoteDataString);
            }
            catch (Exception ex)
            {
                remoteData = new JObject
                {
                    new JProperty("error", ex.ToString())
                }; 
            }

            var data = new {
                IncomingUser = localData,
                BackendUser = remoteData
            };

            return Content(JsonConvert.SerializeObject(data), "application/json");
        }
    }
}