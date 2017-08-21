using System;
using System.Collections.Generic;
using System.IO.Packaging;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Tectil.NCommand.Contract;
namespace NuGetSign
{
    
    class SignCommands
    {
        [Command(Name = "sign")]
        public string Sign(
            [Argument(Description ="Path to nupkg" )] string nupkg,
            [Argument(Description ="Path to PFX")] string pfx,
            [Argument(Description = "PFX Password")] string passwd
            )
        {
            Package package = Package.Open(nupkg);
            X509Certificate cert = null;
            if (!String.IsNullOrEmpty(pfx))
            {
                cert = new X509Certificate(pfx, passwd);
            }
            SignAllParts(package, cert);
            
            return "ok";
        }

        [Command()]
        public string Verify(
            [Argument(Description = "Path to nupkg")] string nupkg,
            [Argument(Description = "Full Vertification", DefaultValue = false)] bool full
            )
        {
            Package package = Package.Open(nupkg);
            PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(package);       
            return  dsm.VerifySignatures(full).ToString();
        }

        [Command()]
        public void RemoveSignatures(
            [Argument(Description = "Path to nupkg")] string nupkg)
        {
            Package package = Package.Open(nupkg);
            PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(package);
            Console.WriteLine("Write YES to confirm removing all signatures");
            var confirmed = Console.ReadLine();
            if (confirmed=="YES")
            {
                dsm.RemoveAllSignatures();
            }
            package.Close();
        }


        [Command()]
        public string View(
            [Argument(Description = "Path to nupkg")] string nupkg,
            [Argument(Description = "View All Cert Info", DefaultValue = false)] bool complete
            )
        {
            string result = string.Empty;
            Package package = Package.Open(nupkg);
            PackageDigitalSignatureManager dsm = new PackageDigitalSignatureManager(package);
            foreach (var sign in dsm.Signatures)
            {
                result += $"Time: {sign.SigningTime} From: {sign.Signer.Subject} \r\n";
                if (complete)
                {
                    result += $"\t\t CA: {sign.Signer.Issuer}\r\n";
                    result += $"\t\t Serial: {sign.Signer.GetSerialNumberString()}\r\n";
                    result += $"\t\t Key: {sign.Signer.GetKeyAlgorithm()}\r\n";
                    result += $"\t\t Expires: {sign.Signer.GetExpirationDateString()}\r\n";
                }
            }
            return result;
        }

        private static void SignAllParts(Package package, X509Certificate cert = null)
        {
            if (package == null)
                throw new ArgumentNullException("SignAllParts(package)");

            // Create the DigitalSignature Manager
            PackageDigitalSignatureManager dsm =
                new PackageDigitalSignatureManager(package);
            dsm.CertificateOption =
                CertificateEmbeddingOption.InSignaturePart;

            // Create a list of all the part URIs in the package to sign
            // (GetParts() also includes PackageRelationship parts).
            System.Collections.Generic.List<Uri> toSign =
                new System.Collections.Generic.List<Uri>();
            foreach (PackagePart packagePart in package.GetParts())
            {
                // Add all package parts to the list for signing.
                toSign.Add(packagePart.Uri);
            }

            // Add the URI for SignatureOrigin PackageRelationship part.
            // The SignatureOrigin relationship is created when Sign() is called.
            // Signing the SignatureOrigin relationship disables counter-signatures.
            toSign.Add(PackUriHelper.GetRelationshipPartUri(dsm.SignatureOrigin));

            // Also sign the SignatureOrigin part.
            toSign.Add(dsm.SignatureOrigin);

            // Add the package relationship to the signature origin to be signed.
            toSign.Add(PackUriHelper.GetRelationshipPartUri(new Uri("/", UriKind.RelativeOrAbsolute)));

            try
            {
                if (cert == null)
                {

                    // Sign() will prompt the user to select a Certificate to sign with.

                    dsm.Sign(toSign);
                }
                else
                {
                    dsm.Sign(toSign, cert);
                }
            }

            // If there are no certificates or the SmartCard manager is
            // not running, catch the exception and show an error message.
            catch (CryptographicException ex)
            {
                /*
                MessageBox.Show(
                    "Cannot Sign\n" + ex.Message,
                    "No Digital Certificates Available",
                    MessageBoxButton.OK,
                    MessageBoxImage.Exclamation);
                    */
                Console.WriteLine("Cannot Sign\n" + ex.Message);
            }

        }// end:SignAllParts()


    }
}
