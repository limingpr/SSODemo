using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace SSO
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                TestLoginApi();

            }
        }

        public async static void TestLoginApi()
        {
            HttpClientHandler handler = new HttpClientHandler();
            handler.UseCookies = true;//因为采用Form验证，所以需要使用Cookie来记录身份登录信息
            HttpClient client = new HttpClient(handler);

            Console.WriteLine("Login>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
            var response = await client.GetAsync("http://localhost:7278/api/sso?systemcode=name");
            var r = await response.Content.ReadAsAsync<dynamic>();
            Console.WriteLine("StatusCode:{0}", response.StatusCode);
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine("Msg:{1}", response.StatusCode, r.Message);
                return;
            }
            Console.WriteLine("Msg:{1}", response.StatusCode, r);

            var getCookies = handler.CookieContainer.GetCookies(new Uri("http://localhost:7278/"));
            Console.WriteLine("获取到的cookie数量：" + getCookies.Count);
            Console.WriteLine("获取到的cookie：");
            for (int i = 0; i < getCookies.Count; i++)
            {
                Console.WriteLine(getCookies[i].Name + ":" + getCookies[i].Value);
                
            }


            //Console.WriteLine("GetValues>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
            //response = await client.GetAsync("http://localhost:11099/api/test/");
            //var r2 = await response.Content.ReadAsAsync<IEnumerable<string>>();
            //foreach (string item in r2)
            //{
            //    Console.WriteLine("GetValues - Item Value:{0}", item);
            //}

        }
    }
}