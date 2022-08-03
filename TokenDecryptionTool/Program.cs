using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace TokenDecryptionTool
{
    class Program
    {
        private static readonly string certThumbprint = "your_cert_thumbprint_here";
        static void Main(string[] args)
        {
            var token = "your_token_here";
            var decodedtoken = DecryptToken(token);
            Console.WriteLine(decodedtoken);
        }

        public static X509Certificate2 GetClientCertificate(string ClientCertificateThumbprint)
        {
            X509Certificate2 cert;
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByThumbprint, ClientCertificateThumbprint, false);

                if (certificates.Count == 0)
                {
                    throw new ArgumentException("Couldn't find any certificates with ClientCertificateThumbprint");
                }

                cert = certificates[0];
            }
            finally
            {
                store.Close();
            }
            return cert;
        }

        private static string DecryptToken(string token)
        {
            SPJwtSecurityTokenHandler m_JwtTokenHandler = new SPJwtSecurityTokenHandler();
            try
            {
                string decryptedToken;
                if (!string.IsNullOrWhiteSpace(token))
                {
                    JwtSecurityToken jwtToken = new JwtSecurityToken(token);

                    decryptedToken = m_JwtTokenHandler.DecryptToken(
                        jwtToken,
                        new TokenValidationParameters()
                        {
                            TokenDecryptionKey = GetTokenDecryptionKey(),
                            TokenDecryptionKeys = GetTokenDecryptionKeys(),
                        });
                }
                else
                {
                    decryptedToken = token;
                }

                return decryptedToken;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static RsaSecurityKey GetTokenDecryptionKey()
        {
            X509Certificate2 primaryCertificate = GetClientCertificate(certThumbprint);
            RsaSecurityKey PrimaryCertificateKey = new RsaSecurityKey(primaryCertificate.GetRSAPrivateKey().ExportParameters(true));
            return PrimaryCertificateKey;
        }

        public static IEnumerable<SecurityKey> GetTokenDecryptionKeys()
        {
            yield return GetTokenDecryptionKey();
        }
    }
    public class SPJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        static SPJwtSecurityTokenHandler()
        {

        }
        public string DecryptToken(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            return base.DecryptToken(jwtToken, validationParameters);
        }
    }
}
