using Newtonsoft.Json;
using OThinker.H3.Controllers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;

namespace SSO.Controllers
{
    public class SSOController : ApiController
    {
        /// <summary>
        /// SSO统一接入接口
        /// </summary>
        /// <param name="systemcode">系统编码</param>
        /// <param name="returnurl">跳转URL地址</param>
        public void Get(string systemcode, string returnurl)
        {
            var context = HttpContext.Current;
            string token = null;
            //1、判断本地是否储存了systemcode的Cookie
            if (context.Request.Cookies[systemcode] != null)
            {
                token = context.Request.Cookies[systemcode].Value;
            }

            if (!string.IsNullOrEmpty(token))
            {
                //2 有token,跳转到returnurl，并带上token参数。
                var NewUrl = MakeReturnUrl(context.Request["returnurl"], token);
                context.Response.Redirect(NewUrl, true);
            }
            else
            {
                //3 浏览器没传过来h3bpmsso这个cookie，判定为未登录
                //4 跳转到登录页面，带上登录成功后的返回地址
                var url = string.Format(@"~/login.html?systemcode={0}&returnurl={1}", systemcode, returnurl);
                context.Response.Redirect(url, true);

            }
        }


        [EnableCors("*", "*", "*", SupportsCredentials = true)]
        public string GetToken(HttpRequestMessage request, string systemcode)
        {
            string token = "";
            var cookies = System.Web.HttpContext.Current.Request.Cookies;
            CookieHeaderValue cookie = request.Headers.GetCookies(systemcode).FirstOrDefault();
            if (cookie != null)
            {
                token = cookie[systemcode].Value;
            }
            return token;

        }

        /// <summary>
        /// 登录接口
        /// </summary>
        /// <param name="systemcode"></param>
        /// <returns></returns>
        [HttpPost]
        public string Login(string systemcode)
        {
            var context = HttpContext.Current;
            var request = context.Request;
            string usercode = request["usercode"].ToString();
            string password = request["pwd"].ToString();
            if (string.IsNullOrEmpty(systemcode) || systemcode == "null")
            {
                systemcode = "";
            }
            return DoLogin(usercode, password, systemcode);


        }

        /// <summary>
        /// 登录接口-供其他系统API调用
        /// </summary>
        /// <param name="usercode"></param>
        /// <param name="pwd"></param>
        /// <param name="systemcode"></param>
        /// <returns></returns>
        [HttpGet]
        public string Login(string usercode, string pwd, string systemcode)
        {

            return DoLogin(usercode, pwd, systemcode);
        }

        /// <summary>
        /// 登录事件
        /// </summary>
        /// <param name="usercode"></param>
        /// <param name="password"></param>
        /// <param name="systemcode"></param>
        /// <returns></returns>
        public string DoLogin(string usercode, string password, string systemcode)
        {
            var context = HttpContext.Current;

            //使用H3的认证方式，支持Form认证和AD认证
            var loginResult = UserValidatorFactory.Login(
                    OThinker.Clusterware.AuthenticationType.Forms,
                    string.Empty,
                    usercode,
                    password,
                    OThinker.H3.Site.PortalType.Portal);
            if (loginResult)
            {
                var user = OThinker.H3.Controllers.AppUtility.Engine.Organization.GetUserByCode(usercode);

                //此处客户要求每个系统单独生成Token，做的处理，只要任一系统登录成功，都为接入单点登录的所有网站生成Token
                //查找注册在H3单点登录列表中的所有站点
                var systemlist = OThinker.H3.Controllers.AppUtility.Engine.SSOManager.GetSSOSystemList();
                foreach (var item in systemlist)
                {
                    //5 登录成功，创建用户账号对应的token xxx
                    //Token的加密组合：系统编码+登录名+时间戳
                    var p_param = string.Format("{0}|{1}|{2}", item.SystemCode, usercode, System.DateTime.Now.Ticks);

                    var key = GetSecretBySystemcode(item.SystemCode);

                    var token = EncryptHelper.Encrypt(p_param, key);

                    //更改系统状态，允许调用接口进行Token验证
                    item.AllowGetToken = true;
                    OThinker.H3.Controllers.AppUtility.Engine.SSOManager.UpdateSSOSystem(item);


                    //6 把token写到本站cookie；
                    context.Response.SetCookie(new HttpCookie(item.SystemCode, token));

                }

                //这个cookie和sso流程无关，是方便SSO的login.html前端页面显示用户名用的。
                context.Response.SetCookie(new HttpCookie("username", user.Name));

                var mesg = new Message { UserCode = user.Code };

                if (!string.IsNullOrEmpty(systemcode))
                {
                    //7 跳转到returnurl并带上token。此处只输出token，在前端页面回调中执行跳转。

                    mesg.Url = GetSystemUrl(systemcode);

                    mesg.Token = context.Request.Cookies[systemcode] != null ? context.Request.Cookies[systemcode].Value : "";


                }

                return Newtonsoft.Json.JsonConvert.SerializeObject(mesg);
            }
            else
            {
                var mesg = new Message { UserCode = "", ErrCode = "1000", ErrMsg = "用户名或密码错误" };
                return Newtonsoft.Json.JsonConvert.SerializeObject(mesg);

            }
        }

        /// <summary>
        /// 验证接口
        /// </summary>
        /// <param name="systemcode"></param>
        /// <param name="secret"></param>
        /// <param name="h3bpmsso"></param>
        /// <returns></returns>
        [HttpGet]
        public string Validate(string systemcode, string h3bpmsso)
        {
            var mes = new Message()
            {
                ErrCode = "0",
                ErrMsg = ""
            };
            if (string.IsNullOrEmpty(h3bpmsso))
            {
                mes.ErrCode = "1003";
                mes.ErrMsg = "Token IS NULL";
                mes.UserCode = "";

                return JsonConvert.SerializeObject(mes);
            }
            var context = HttpContext.Current;

            var targetsystem = OThinker.H3.Controllers.AppUtility.Engine.SSOManager.GetSSOSystem(systemcode);
            if (targetsystem != null)
            {
                if(!targetsystem.AllowGetToken)
                {
                    mes.ErrCode = "1006";
                    mes.ErrMsg = "系统已经处于注销状态，请重新登录";
                    mes.UserCode = "";

                    return JsonConvert.SerializeObject(mes);

                }
                var key = GetSecretBySystemcode(systemcode);

                var Userinfo = EncryptHelper.Decrypt(h3bpmsso, key);

                if (!string.IsNullOrEmpty(Userinfo))
                {
                    //如果TimeSpan参数不为空，则验证Token是否超时
                    var TimeSpan = ConfigurationManager.AppSettings["TimeSpan"] + string.Empty;
                    if (!string.IsNullOrEmpty(TimeSpan))
                    {
                        var oldTicks = long.Parse(Userinfo.Split('|')[2]);
                        long nowTicks = DateTime.Now.Ticks;
                        double n = (nowTicks - oldTicks) / (10000000 * 60);
                        if (n > double.Parse(TimeSpan))
                        {
                            mes.ErrCode = "1002";
                            mes.ErrMsg = "Token超时";
                            return JsonConvert.SerializeObject(mes);

                        }
                    }
                    var usercode = Userinfo.Split('|')[1];
                    mes.UserCode = usercode;
                    return mes.UserCode;
                    //更新h3bpmsso的时间戳 TODO
                }
                else
                {
                    //todo:要检查账号所在域名是否正确。
                    string accountStr = null;
                    if (context.User != null && context.User.Identity != null)
                    {
                        accountStr = context.User.Identity.Name.Split('\\')[1].ToLower();
                    }

                    if (!string.IsNullOrEmpty(accountStr))
                    {
                        var user = OThinker.H3.Controllers.AppUtility.Engine.Organization.GetUserByCode(accountStr);
                        if (user != null)
                        {
                            mes.UserCode = user.Code;

                        }
                    }
                }

                if (mes.UserCode != null)
                {
                    //13. 验证通过。
                    //14. 告知token有效，并附带允许站点获取的用户信息。

                    //todo:实际场景中，应该根据请求的server-key，只传递该server能看到的用户信息。
                    return JsonConvert.SerializeObject(mes);
                }
                else
                {
                    //解析失败
                    mes.ErrCode = "1004";
                    mes.ErrMsg = "Token无效，未能解析出用户信息";
                    mes.UserCode = "";

                    return JsonConvert.SerializeObject(mes);

                }
            }
            else
            {
                mes.ErrCode = "1001";
                mes.ErrMsg = "此系统编码不在H3统一认证中心";
                return JsonConvert.SerializeObject(mes);

            }



        }

        /// <summary>
        /// 生成带Token的url地址
        /// </summary>
        /// <param name="returnUrlQuery"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        private string MakeReturnUrl(string returnUrlQuery, string token)
        {
            var decoded = HttpUtility.UrlDecode(returnUrlQuery);
            var toReturn = decoded.Contains('?') ? string.Format("{0}&h3bpmsso={1}", decoded, token) : string.Format("{0}?h3bpmsso={1}", decoded, token);
            return toReturn;
        }

        [HttpGet]
        /// <summary>
        /// 登出方法
        /// </summary>
        public void Logout()
        {
            HttpContextBase context = (HttpContextBase)Request.Properties["MS_HttpContext"];//获取传统context

            context.Response.Redirect("~/login.html?action=logout");
        }

        /// <summary>
        /// 清理本地凭证
        /// </summary>
        /// <param name="systemcode"></param>
        /// <returns></returns>
        [HttpGet]

        public string DeleteSssion(string systemcode)
        {
            try
            {
                HttpContextBase context = (HttpContextBase)Request.Properties["MS_HttpContext"];//获取传统context
                var list = OThinker.H3.Controllers.AppUtility.Engine.SSOManager.GetSSOSystemList();
                foreach (var item in list)
                {
                    HttpCookie aCookie = new HttpCookie(item.SystemCode)
                    {
                        Expires = DateTime.Now.AddDays(-1)
                    };
                    context.Response.Cookies.Add(aCookie);

                    //更改系统状态，不允许进行验证，防止系统注销后，用旧秘钥去验证
                    item.AllowGetToken = false;
                    OThinker.H3.Controllers.AppUtility.Engine.SSOManager.UpdateSSOSystem(item);
                }
                HttpCookie aCookie2 = new HttpCookie("username")
                {
                    Expires = DateTime.Now.AddDays(-1)
                };
                context.Response.Cookies.Add(aCookie2);


                return JsonConvert.SerializeObject(new Message { ErrCode = "0" });

            }
            catch (Exception ex)
            {

                return JsonConvert.SerializeObject(new Message { ErrCode = "1005", ErrMsg = ex.Message });
            }

        }

        /// <summary>
        /// 获取系统秘钥
        /// </summary>
        /// <param name="SystemCode"></param>
        /// <returns></returns>
        public String GetSecretBySystemcode(String SystemCode)
        {
            var targetsystem = OThinker.H3.Controllers.AppUtility.Engine.SSOManager.GetSSOSystem(SystemCode);
            if (targetsystem != null)
            {
                return targetsystem.Secret;

            }
            else
            {
                return SystemCode;
            }

        }

        /// <summary>
        /// 获取系统默认跳转页面地址
        /// </summary>
        /// <param name="targetCode"></param>
        /// <returns></returns>
        public String GetSystemUrl(String targetCode)
        {
            var targetsystem = OThinker.H3.Controllers.AppUtility.Engine.SSOManager.GetSSOSystem(targetCode);
            if (targetsystem != null)
            {
                return targetsystem.DefaultUrl;

            }
            else
            {
                return "";
            }

        }

    }

    internal class Message
    {
        public Message()
        {
        }

        public string ErrCode { get; internal set; }
        public string ErrMsg { get; internal set; }
        public string UserCode { get; internal set; }
        public string Url { get; internal set; }

        public string Token { get; internal set; }

    }
}