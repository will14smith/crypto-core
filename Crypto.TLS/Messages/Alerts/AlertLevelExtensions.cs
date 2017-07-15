namespace Crypto.TLS.Messages.Alerts
{
    public static class AlertLevelExtensions
    {
        private static readonly AlertLevel[] AllowedDescLevels;

        static AlertLevelExtensions()
        {
            AllowedDescLevels = new AlertLevel[255];

            AllowedDescLevels[(int)AlertDescription.CloseNotify] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnexpectedMessage] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.BadRecordMAC] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecryptionFailedReserved] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.RecordOverflow] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecompressionFailure] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.HandshakeFailure] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.NoCertificateReserved] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.BadCertificate] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnsupportedCertificate] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateRevoked] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateExpired] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.CertificateUnknown] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.IllegalParameter] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UnknownCa] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.AccessDenied] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecodeError] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.DecryptError] = AlertLevel.Warning | AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.ExportRestrictionReserved] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.ProtocolVersion] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.InsufficientSecurity] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.InternalError] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.UserCanceled] = AlertLevel.Fatal;
            AllowedDescLevels[(int)AlertDescription.NoRenegotiation] = AlertLevel.Warning;
            AllowedDescLevels[(int)AlertDescription.UnsupportedExtension] = AlertLevel.Warning;
        }

        public static bool IsAllowed(this AlertLevel level, AlertDescription desc)
        {
            return (AllowedDescLevels[(int)desc] & level) != 0;
        }
    }
}