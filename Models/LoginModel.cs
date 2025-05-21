
using System;
using System.ComponentModel.DataAnnotations;

namespace CrudMap.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string EmailId { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Full Name is required")]
        public string FullName { get; set; }

        public DateTime Date { get; set; }

        [Required(ErrorMessage = "Please select a country")]
        public int CountryId { get; set; }

        public string CountryName { get; set; }

        [Required]
        public string Code { get; set; }


        [Required]
        public string NewPassword { get; set; }

        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
