using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Text;
using System.Security.Cryptography;

public class EncryptHelper
{

    /// <summary>
    /// DES数据加密
    /// </summary>
    /// <param name="targetValue">目标值</param>
    /// <param name="key">密钥</param>
    /// <returns>加密值</returns>
    private static string EncryptString(string targetValue, string key)
    {
        return Encrypt(targetValue, key);
    }

    /// <summary>
    /// DES数据解密
    /// </summary>
    /// <param name="targetValue"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    private static string DecryptString(string targetValue, string key)
    {
        return Decrypt(targetValue, key);
    }


    /// <summary>
    /// DES数据加密
    /// </summary>
    /// <param name="targetValue">目标值</param>
    /// <param name="key">密钥</param>
    /// <returns>加密值</returns>
    public static string Encrypt(string targetValue, string key)
    {
        if (string.IsNullOrEmpty(targetValue))
        {
            return string.Empty;
        }

        try
        {

        

        var returnValue = new StringBuilder();
        var des = new DESCryptoServiceProvider();
        byte[] inputByteArray = Encoding.Default.GetBytes(targetValue);
        // 通过两次哈希密码设置对称算法的初始化向量   
        des.Key = Encoding.ASCII.GetBytes(FormsAuthentication.HashPasswordForStoringInConfigFile
                                              (FormsAuthentication.HashPasswordForStoringInConfigFile(key, "md5").
                                                   Substring(0, 8), "sha1").Substring(0, 8));
        // 通过两次哈希密码设置算法的机密密钥   
        des.IV = Encoding.ASCII.GetBytes(FormsAuthentication.HashPasswordForStoringInConfigFile
                                             (FormsAuthentication.HashPasswordForStoringInConfigFile(key, "md5")
                                                  .Substring(0, 8), "md5").Substring(0, 8));
        var ms = new MemoryStream();
        var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(inputByteArray, 0, inputByteArray.Length);
        cs.FlushFinalBlock();
        foreach (byte b in ms.ToArray())
        {
            returnValue.AppendFormat("{0:X2}", b);
        }
        return returnValue.ToString();
        }
        catch (Exception)
        {

            return "";
        }
    }



    /// <summary>
    /// DES数据解密
    /// </summary>
    /// <param name="targetValue"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public static string Decrypt(string targetValue, string key)
    {
        if (string.IsNullOrEmpty(targetValue))
        {
            return string.Empty;
        }
        try
        {


            // 定义DES加密对象
            var des = new DESCryptoServiceProvider();
            int len = targetValue.Length / 2;
            var inputByteArray = new byte[len];
            int x, i;
            for (x = 0; x < len; x++)
            {
                i = Convert.ToInt32(targetValue.Substring(x * 2, 2), 16);
                inputByteArray[x] = (byte)i;
            }
            // 通过两次哈希密码设置对称算法的初始化向量   
            des.Key = Encoding.ASCII.GetBytes(FormsAuthentication.HashPasswordForStoringInConfigFile
                                                  (FormsAuthentication.HashPasswordForStoringInConfigFile(key, "md5").
                                                       Substring(0, 8), "sha1").Substring(0, 8));
            // 通过两次哈希密码设置算法的机密密钥   
            des.IV = Encoding.ASCII.GetBytes(FormsAuthentication.HashPasswordForStoringInConfigFile
                                                 (FormsAuthentication.HashPasswordForStoringInConfigFile(key, "md5")
                                                      .Substring(0, 8), "md5").Substring(0, 8));
            // 定义内存流
            var ms = new MemoryStream();
            // 定义加密流
            var cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            return Encoding.Default.GetString(ms.ToArray());
        }
        catch (Exception ex)
        {

            return "";
        }
    }
}