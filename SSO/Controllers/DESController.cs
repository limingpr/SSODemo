using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace SSO.Controllers
{
    public class DESController : ApiController
    {
        [HttpGet]
        public string GetEncrypt(string pwd, string key)
        {
            return EncryptHelper.Encrypt(pwd, key);
        }

        [HttpGet]
        public string GetDecrypt(string encryptedString, string key)
        {
            return EncryptHelper.Decrypt(encryptedString, key);
        }
    }
}
