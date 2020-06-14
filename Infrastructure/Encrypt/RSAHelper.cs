using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using XC.RSAUtil;

namespace Infrastructure.Encrypt
{
    /// <summary>
    /// Install-Package XC.RSAUtil(https://github.com/stulzq/RSAUtil)
    /// </summary>
    public class RSAHelper
    {
        #region 1、生成密钥
        /// <summary>
        /// XML格式的RSA密钥
        /// </summary>
        /// <returns></returns>
        public static string CreateXMLKey()
        {
            var keyList = RsaKeyGenerator.XmlKey(2048);
            var privateKey = keyList[0];
            var publicKey = keyList[1];
            return $"私钥：{privateKey}\n公钥：{publicKey}";
        }

        /// <summary>
        /// Pkcs1格式的RSA密钥
        /// </summary>
        /// <returns></returns>
        public static string CreatePkcs1Key()
        {
            var keyList = RsaKeyGenerator.Pkcs1Key(2048, true);
            var privateKey = keyList[0];
            var publicKey = keyList[1];
            return $"私钥：{privateKey}\n公钥：{publicKey}";
        }

        /// <summary>
        /// Pkcs8格式的RSA密钥
        /// </summary>
        /// <returns></returns>
        public static string CreatePkcs8Key()
        {
            var keyList = RsaKeyGenerator.Pkcs8Key(2048, true);
            var privateKey = keyList[0];
            var publicKey = keyList[1];
            return $"私钥：{privateKey}\n公钥：{publicKey}";
        }
        #endregion

        #region 2、RSA密钥转换
        /// <summary>
        /// XML-> Pkcs1
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyXmlToPkcs1(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyXmlToPkcs1(privateKeyXml);
            }
            catch(Exception ex)
            {
                return ex.Message;
            }            
        }
        /// <summary>
        /// XML-> Pkcs1
        /// </summary>
        /// <param name="publicKeyXml">公钥</param>
        /// <returns></returns>
        public static string ConvertPublicKeyXmlToPkcs1(string publicKeyXml)
        {
            if (publicKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PublicKeyXmlToPem(publicKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// XML-> Pkcs8
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyXmlToPkcs8(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyXmlToPkcs8(privateKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// XML-> Pkcs8
        /// </summary>
        /// <param name="publicKeyXml">公钥</param>
        /// <returns></returns>
        public static string ConvertPublicKeyXmlToPem(string publicKeyXml)
        {
            if (publicKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PublicKeyXmlToPem(publicKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs1-> XML
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs1ToXml(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyPkcs1ToXml(privateKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs1||Pkcs8-> XML
        /// </summary>
        /// <param name="publicKeyXml">公钥</param>
        /// <returns></returns>
        public static string ConvertPublicKeyPemToXml(string publicKeyXml)
        {
            if (publicKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PublicKeyPemToXml(publicKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs1-> Pkcs8
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs1ToPkcs8(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyPkcs1ToPkcs8(privateKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs1-> Pkcs8（不需要转换）
        /// </summary>
        /// <param name="publicKeyXml">公钥</param>
        /// <returns></returns>
        public static string ConvertPublicKeyPkcs1ToPkcs8(string publicKeyXml)
        {
            if (publicKeyXml is null)
            {
                return "null";
            }
            return publicKeyXml;
        }
        /// <summary>
        /// Pkcs8-> XML
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs8ToXml(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyPkcs8ToXml(privateKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs8-> Pkcs1
        /// </summary>
        /// <param name="privateKeyXml">私钥</param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs8ToPkcs1(string privateKeyXml)
        {
            if (privateKeyXml is null)
            {
                return "null";
            }
            try
            {
                return RsaKeyConvert.PrivateKeyPkcs8ToPkcs1(privateKeyXml);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// Pkcs1-> Pkcs8（不需要转换）
        /// </summary>
        /// <param name="publicKeyXml">公钥</param>
        /// <returns></returns>
        public static string ConvertPublicKeyPkcs8ToPkcs1(string publicKeyXml)
        {
            if (publicKeyXml is null)
            {
                return "null";
            }
            return publicKeyXml;
        }
        #endregion

        #region 3、XML，Pkcs1，Pkcs8分别对应类：RsaXmlUtil，RsaPkcs1Util，RsaPkcs8Util。它们继承自抽象类RSAUtilBase
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="baseObj"></param>
        /// <param name="encryptData"></param>
        /// <returns></returns>
        public static string Encrypt(RSAUtilBase baseObj, string encryptData)
        {
            if (baseObj is null)
            {
                throw new ArgumentNullException(nameof(baseObj));
            }
            try
            {
                //RSAEncryptionPadding ：OaepSHA1 || OaepSHA384 ...
                return baseObj.Encrypt(encryptData, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="baseObj"></param>
        /// <param name="decryptData"></param>
        /// <returns></returns>
        public static string Decrypt(RSAUtilBase baseObj, string decryptData)
        {
            if (baseObj is null)
            {
                throw new ArgumentNullException(nameof(baseObj));
            }
            try
            {
                //RSAEncryptionPadding ：OaepSHA1 || OaepSHA384 ...
                return baseObj.Decrypt(decryptData, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="baseObj"></param>
        /// <param name="signData"></param>
        /// <returns></returns>
        public static string SignData(RSAUtilBase baseObj, string signData)
        {
            if (baseObj is null)
            {
                throw new ArgumentNullException(nameof(baseObj));
            }
            try
            {
                return baseObj.SignData(signData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="baseObj"></param>
        /// <param name="data"></param>
        /// <param name="sign"></param>
        /// <returns></returns>
        public static bool SignData(RSAUtilBase baseObj, string data, string sign)
        {
            if (baseObj is null)
            {
                throw new ArgumentNullException(nameof(baseObj));
            }
            try
            {
                return baseObj.VerifyData(data, sign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                throw new ArgumentNullException(nameof(baseObj));
            }
        }
        #endregion

        #region 4、PEM格式化
        /// <summary>
        /// 格式化Pkcs1格式私钥
        /// </summary>
        /// <param name="pkcs1PrivateKey"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormat(string pkcs1PrivateKey)
        {
            if (pkcs1PrivateKey is null)
            {
                return "null";
            }
            try
            {
                return RsaPemFormatHelper.Pkcs1PrivateKeyFormat(pkcs1PrivateKey);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 删除Pkcs1格式私钥格式
        /// </summary>
        /// <param name="removePkcs1PrivateKey"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormatRemove(string removePkcs1PrivateKey)
        {
            if (removePkcs1PrivateKey is null)
            {
                return "null";
            }
            try
            {
                return RsaPemFormatHelper.Pkcs1PrivateKeyFormatRemove(removePkcs1PrivateKey);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 格式化Pkcs8格式私钥
        /// </summary>
        /// <param name="pkcs8PrivateKey"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormat(string pkcs8PrivateKey)
        {
            if (pkcs8PrivateKey is null)
            {
                return "null";
            }
            try
            {
                return RsaPemFormatHelper.Pkcs8PrivateKeyFormat(pkcs8PrivateKey);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        /// <summary>
        /// 删除Pkcs1格式私钥格式
        /// </summary>
        /// <param name="removePkcs8PrivateKey"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormatRemove(string removePkcs8PrivateKey)
        {
            if (removePkcs8PrivateKey is null)
            {
                return "null";
            }
            try
            {
                return RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(removePkcs8PrivateKey);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }           
        }
        #endregion
    }
}
