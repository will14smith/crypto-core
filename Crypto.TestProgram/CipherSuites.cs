using Crypto.TLS;
using Crypto.TLS.RSA;
using Crypto.TLS.Services;
using Microsoft.Extensions.DependencyInjection;
using Crypto.TLS.AES;
using Crypto.TLS.DH;
using Crypto.TLS.EC;
using Crypto.TLS.Identifiers;
using Crypto.TLS.SHA;
using Crypto.TLS.GCM;

namespace Crypto.TestProgram
{
    public static class CipherSuites
    {
        public static void AddCipherSuites(this IServiceCollection services)
        {
            AddStandard(services);
            AddGCM(services);
            AddEC(services);
            AddECGCM(services);
        }

        #region standard

        public static readonly CipherSuite TLS_RSA_WITH_NULL_MD5 = (CipherSuite)0x0001;
        public static readonly CipherSuite TLS_RSA_WITH_NULL_SHA = (CipherSuite)0x0002;
        public static readonly CipherSuite TLS_RSA_WITH_NULL_SHA256 = (CipherSuite)0x003B;
        public static readonly CipherSuite TLS_RSA_WITH_RC4_128_MD5 = (CipherSuite)0x0004;
        public static readonly CipherSuite TLS_RSA_WITH_RC4_128_SHA = (CipherSuite)0x0005;
        public static readonly CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x000A;
        public static readonly CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = (CipherSuite)0x002F;
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = (CipherSuite)0x0035;
        public static readonly CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x003C;
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x003D;
        public static readonly CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x000D;
        public static readonly CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x0010;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x0013;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x0016;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA = (CipherSuite)0x0030;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA = (CipherSuite)0x0031;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA = (CipherSuite)0x0032;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA = (CipherSuite)0x0033;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA = (CipherSuite)0x0036;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA = (CipherSuite)0x0037;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA = (CipherSuite)0x0038;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA = (CipherSuite)0x0039;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x003E;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x003F;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x0040;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x0067;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x0068;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x0069;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x006A;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x006B;
        public static readonly CipherSuite TLS_DH_anon_WITH_RC4_128_MD5 = (CipherSuite)0x0018;
        public static readonly CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0x001B;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA = (CipherSuite)0x0034;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA = (CipherSuite)0x003A;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA256 = (CipherSuite)0x006C;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA256 = (CipherSuite)0x006D;

        private static void AddStandard(IServiceCollection services)
        {
            //TODO services.RegisterCipherSuite(TLS_RSA_WITH_NULL_MD5, TLSCipherAlgorithm.Null, null, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_NULL_SHA256, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            //TODO services.RegisterCipherSuite(TLS_RSA_WITH_RC4_128_MD5, null, null, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            //TODO services.RegisterCipherSuite(TLS_RSA_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            //TODO services.RegisterCipherSuite(TLS_RSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, null, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, null, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, null, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, null, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, null, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, null, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, null, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, null, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, null, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, null, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_anon_WITH_RC4_128_MD5, null, null, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_256_CBC_SHA256, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA256, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
        }

        #endregion

        #region GCM

        public static readonly CipherSuite TLS_RSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x009C;
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x009D;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x009E;
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x009F;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x00A0;
        public static readonly CipherSuite TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x00A1;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x00A2;
        public static readonly CipherSuite TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x00A3;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x00A4;
        public static readonly CipherSuite TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x00A5;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_128_GCM_SHA256 = (CipherSuite)0x00A6;
        public static readonly CipherSuite TLS_DH_anon_WITH_AES_256_GCM_SHA384 = (CipherSuite)0x00A7;

        public static void AddGCM(IServiceCollection services)
        {
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_RSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, RSAIdentifiers.RSAKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, DHIdentifiers.DHEKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_RSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, null, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, null, DHIdentifiers.DHEKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, null, DHIdentifiers.DHKex);
            //TODO services.RegisterCipherSuite(TLS_DH_DSS_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, null, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
            services.RegisterCipherSuite(TLS_DH_anon_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, TLSSignatureAlgorithm.Anonymous, DHIdentifiers.DHKex);
        }

        #endregion

        #region EC

        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_NULL_SHA = (CipherSuite)0xC001;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_RC4_128_SHA = (CipherSuite)0xC002;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0xC003;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = (CipherSuite)0xC004;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = (CipherSuite)0xC005;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_NULL_SHA = (CipherSuite)0xC006;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = (CipherSuite)0xC007;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0xC008;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = (CipherSuite)0xC009;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = (CipherSuite)0xC00A;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_NULL_SHA = (CipherSuite)0xC00B;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_RC4_128_SHA = (CipherSuite)0xC00C;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0xC00D;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = (CipherSuite)0xC00E;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = (CipherSuite)0xC00F;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_NULL_SHA = (CipherSuite)0xC010;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_RC4_128_SHA = (CipherSuite)0xC011;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0xC012;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = (CipherSuite)0xC013;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = (CipherSuite)0xC014;
        public static readonly CipherSuite TLS_ECDH_anon_WITH_NULL_SHA = (CipherSuite)0xC015;
        public static readonly CipherSuite TLS_ECDH_anon_WITH_RC4_128_SHA = (CipherSuite)0xC016;
        public static readonly CipherSuite TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = (CipherSuite)0xC017;
        public static readonly CipherSuite TLS_ECDH_anon_WITH_AES_128_CBC_SHA = (CipherSuite)0xC018;
        public static readonly CipherSuite TLS_ECDH_anon_WITH_AES_256_CBC_SHA = (CipherSuite)0xC01;

        public static void AddEC(IServiceCollection services)
        {
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, null);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, null);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_anon_WITH_NULL_SHA, TLSCipherAlgorithm.Null, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_anon_WITH_RC4_128_SHA, null, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, null, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_anon_WITH_AES_128_CBC_SHA, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_anon_WITH_AES_256_CBC_SHA, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA1, TLSSignatureAlgorithm.Anonymous, null);
        }

        #endregion

        #region ECGCM

        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0xC023;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = (CipherSuite)0xC024;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0xC025;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = (CipherSuite)0xC026;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0xC027;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = (CipherSuite)0xC028;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = (CipherSuite)0xC029;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = (CipherSuite)0xC02A;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0xC02B;
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0xC02C;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0xC02D;
        public static readonly CipherSuite TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0xC02E;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0xC02F;
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0xC030;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = (CipherSuite)0xC031;
        public static readonly CipherSuite TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = (CipherSuite)0xC032;

        public static void AddECGCM(IServiceCollection services)
        {
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA384, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA384, ECIdentifiers.ECDSA, null);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, AESIdentifiers.AES128_CBC, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, AESIdentifiers.AES256_CBC, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, null);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, ECIdentifiers.ECDSA, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, ECIdentifiers.ECDSA, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, ECIdentifiers.ECDSA, null);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            services.RegisterCipherSuite(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, ECIdentifiers.ECDHE);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, GCMIdentifiers.AES128_GCM, SHAIdentifiers.SHA256, RSAIdentifiers.RSASig, null);
            //TODO services.RegisterCipherSuite(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, GCMIdentifiers.AES256_GCM, SHAIdentifiers.SHA384, RSAIdentifiers.RSASig, null);
        }

        #endregion
    }
}
