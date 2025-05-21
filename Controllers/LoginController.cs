using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using CrudMap.Models;

namespace CrudMap.Controllers
{
    public class LoginController : Controller
    {
        string conStr = ConfigurationManager.ConnectionStrings["image"].ConnectionString;

        private static Dictionary<string, string> verificationCodes = new Dictionary<string, string>();

        // GET: Login
        public ActionResult Login()
        {
            var model = new LoginModel();

            if (Request.Cookies["UserEmail"] != null)
            {
                model.EmailId = Request.Cookies["UserEmail"].Value;
            }

            return View(model);
        }

        [HttpPost]
        public ActionResult Login(LoginModel model, string RememberMe)
        {
            using (SqlConnection con = new SqlConnection(conStr))
            {
                SqlCommand cmd = new SqlCommand("SELECT Password FROM Register WHERE EmailId = @EmailId", con);
                cmd.Parameters.AddWithValue("@EmailId", model.EmailId);

                con.Open();
                object result = cmd.ExecuteScalar();

                if (result != null && result is byte[] dbPasswordBytes)
                {
                    byte[] inputHashedBytes = PasswordHelper.HashPasswordAsBytes(model.Password);

                    if (dbPasswordBytes.SequenceEqual(inputHashedBytes))
                    {
                        Session["UserEmail"] = model.EmailId;

                        if (!string.IsNullOrEmpty(RememberMe) && RememberMe.ToLower() == "true")
                        {
                            HttpCookie cookie = new HttpCookie("UserEmail");
                            cookie.Value = model.EmailId;
                            cookie.Expires = DateTime.Now.AddDays(7);
                            Response.Cookies.Add(cookie);
                        }

                        return RedirectToAction("Lists", "Teachers");
                    }
                }
            }

            ViewBag.Message = "Invalid Email or Password";
            return View(model);
        }

        public ActionResult Create()
        {
            ViewBag.CountryList = GetCountries();
            return View();
        }

        [HttpPost]
        public ActionResult Create(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.CountryList = GetCountries();
                return View(model);
            }

            using (SqlConnection con = new SqlConnection(conStr))
            {
                byte[] hashedPasswordBytes = PasswordHelper.HashPasswordAsBytes(model.Password);

                SqlCommand cmd = new SqlCommand("SP_InsertRegisterDetails", con);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@FullName", model.FullName);
                cmd.Parameters.AddWithValue("@EmailId", model.EmailId);
                cmd.Parameters.AddWithValue("@Password", hashedPasswordBytes);
                cmd.Parameters.AddWithValue("@Date", DateTime.Now);
                cmd.Parameters.AddWithValue("@CountryId", model.CountryId);

                con.Open();
                SqlDataReader reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string result = reader[0].ToString();
                    TempData["Message"] = result;
                }
            }

            return RedirectToAction("Login");
        }

        private List<SelectListItem> GetCountries()
        {
            List<SelectListItem> countries = new List<SelectListItem>();
            using (SqlConnection con = new SqlConnection(conStr))
            {
                SqlCommand cmd = new SqlCommand("SELECT CountryId, CountryName FROM Country", con);
                con.Open();
                SqlDataReader reader = cmd.ExecuteReader();

                while (reader.Read())
                {
                    countries.Add(new SelectListItem
                    {
                        Value = reader["CountryId"].ToString(),
                        Text = reader["CountryName"].ToString()
                    });
                }
            }
            return countries;
        }

        public ActionResult Logout()
        {
            Session.Clear();
            return RedirectToAction("Login");
        }

        // --- Forgot Password Section ---

        [HttpGet]
        public ActionResult ForgotPassword() => View();

        [HttpPost]
        public ActionResult SendCode(LoginModel model)
        {
            if (!string.IsNullOrEmpty(model.EmailId))
            {
                string code = new Random().Next(100000, 999999).ToString();
                verificationCodes[model.EmailId] = code;

                // ✅ Read email credentials from Web.config
                string email = ConfigurationManager.AppSettings["EmailUser"];
                string password = ConfigurationManager.AppSettings["EmailPassword"];


                MailMessage mail = new MailMessage();
                mail.To.Add(model.EmailId);
                mail.Subject = "Your Verification Code";
                mail.Body = "Your code is: " + code;

                using (SmtpClient smtp = new SmtpClient("smtp.gmail.com", 587))
                {
                    smtp.Credentials = new NetworkCredential("yourEmail@gmail.com", "yourAppPassword");
                    smtp.EnableSsl = true;
                    smtp.Send(mail);
                }

                TempData["Message"] = "Verification code resent!";
                return RedirectToAction("VerifyCode", new { emailId = model.EmailId });
            }

            ModelState.AddModelError("", "Email is required.");
            return View("ForgotPassword");
        }


        [HttpGet]
        public ActionResult VerifyCode(string emailId)
        {
            return View(new LoginModel { EmailId = emailId });
        }

        [HttpPost]
        public ActionResult VerifyCode(LoginModel model)
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString))
            {
                string query = "SELECT VerificationCode, ExpiryDate FROM PasswordReset WHERE Email = @Email";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.Parameters.AddWithValue("@Email", model.EmailId);
                con.Open();
                SqlDataReader reader = cmd.ExecuteReader();

                if (reader.Read())
                {
                    string storedCode = reader["VerificationCode"].ToString();
                    DateTime expiry = Convert.ToDateTime(reader["ExpiryDate"]);

                    if (model.Code == storedCode && DateTime.Now <= expiry)
                    {
                        return RedirectToAction("ResetPassword", new { emailId = model.EmailId });
                    }

                    TempData["Error"] = "Invalid or expired code.";
                    return RedirectToAction("ResendCode", new { emailId = model.EmailId });
                }

                TempData["Error"] = "No verification code found.";
                return RedirectToAction("ForgotPassword");
            }
        }


        [HttpGet]
        public ActionResult ResendCode(string emailId)
        {
            ViewBag.EmailId = emailId;
            return View("VerifyCode", new LoginModel { EmailId = emailId });
        }

        [HttpGet]
        public ActionResult ResetPassword(string emailId)
        {
            return View(new LoginModel { EmailId = emailId });
        }

        [HttpPost]
        public ActionResult ResetPassword(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.NewPassword == model.ConfirmPassword)
                {
                    byte[] hashedPassword = PasswordHelper.HashPasswordAsBytes(model.NewPassword);

                    using (SqlConnection con = new SqlConnection(conStr))
                    {
                        SqlCommand cmd = new SqlCommand("UPDATE Register SET Password=@Password WHERE EmailId=@Email", con);
                        cmd.Parameters.AddWithValue("@Password", hashedPassword);
                        cmd.Parameters.AddWithValue("@Email", model.EmailId);
                        con.Open();
                        cmd.ExecuteNonQuery();
                    }

                    TempData["Message"] = "Password successfully reset!";
                    return RedirectToAction("Login");
                }

                ModelState.AddModelError("", "Passwords do not match.");
            }
            return View(model);
        }
    }
}
