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

            var data = new
            {
                Message = "Hello",
                user.Name,
                user.IsAuthenticated,
                user.AuthenticationType,
                ImpersonationLevel = user.ImpersonationLevel.ToString()
            };

            return Json(data, JsonRequestBehavior.AllowGet);
        }
    }
}