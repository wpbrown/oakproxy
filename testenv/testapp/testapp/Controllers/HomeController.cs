using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
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
            var data = new {
                Message = "Hello",
                User.Identity.Name,
                User.Identity.IsAuthenticated,
                User.Identity.AuthenticationType
            };

            return Json(data, JsonRequestBehavior.AllowGet);
        }
    }
}