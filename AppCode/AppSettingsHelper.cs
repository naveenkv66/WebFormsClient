using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace WebFormsClient.AppCode
{
    public class AppSettingsHelper
    {

        public static string SSO_IACMWebRedirectURL
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["IACMWebRedirectURL"]);
            }
        }

        public static string SSO_Authority
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["Authority"]);
            }
        }
        public static string SSO_ClientId
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["ClientId"]);
            }
        }
        public static string SSO_RedirectUri
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["RedirectUri"]);
            }
        }
        public static string SSO_PostLogoutRedirectUri
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["PostLogoutRedirectUri"]);
            }
        }
        public static string SSO_Scope
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["Scope"]);
            }
        }

        public static string SSO_ClientSecret
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["ClientSecret"]);
            }
        }

        public static string SSO_ResponseType
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["ResponseType"]);
            }
        }

        public static string APIClientId
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["APIClientId"]);
            }
        }
        public static string APIClientSecret
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["APIClientSecret"]);
            }
        }
        public static string APIScope
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["APIScope"]);
            }
        }
        public static string APIResponseType
        {
            get
            {
                return Convert.ToString(ConfigurationManager.AppSettings["APIResponseType"]);
            }
        }
    }
}