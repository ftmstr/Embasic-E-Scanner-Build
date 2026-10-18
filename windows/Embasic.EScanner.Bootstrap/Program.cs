using System;
using System.Security.Cryptography;
using System.Text;

var sample = "ESCANNER-SYNTHETIC-V1";
var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sample)));
if (digest.Length != 64 || !digest.All(Uri.IsHexDigit)) throw new InvalidOperationException("Digest validation failed");
Console.WriteLine("Synthetic contract smoke OK " + digest);
