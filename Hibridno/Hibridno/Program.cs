using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class P2P
{
    public static int Main(String[] args)
    {
        Console.WriteLine("Vnesi 1 za prejemnika in 2 za pošiljatelja");
        string val = Console.ReadLine();
        int a = Convert.ToInt32(val);
        if(a == 1)
        {
            Receiver();
        }

        if (a == 2)
        {
            Sender();
        }
        return 0;
    }

    static byte [] Encrypt (byte[] read, byte[] Key, byte[] IV)
    {

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Padding = PaddingMode.Zeros;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV); //kreira enkriptor

            using (MemoryStream msEncrypt = new MemoryStream()) //stream za enkripcijo
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(read, 0, read.Length);
                    csEncrypt.Close();
                    byte[] encrypted = msEncrypt.ToArray();
                    return encrypted;
                }
            }
        }
    }

    static byte[] Decrypt(byte[] data, byte[] Key, byte[] IV)
    {

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Padding = PaddingMode.Zeros;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(data, 0, data.Length);
                    csDecrypt.Close();
                    byte[] decrypted = msDecrypt.ToArray();
                    return decrypted;
                }
            }
        }
    }

    public static void Receiver()
    {
        IPHostEntry host = Dns.GetHostEntry("localhost"); //ip adress
        IPAddress ipAddress = host.AddressList[0];
        IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

        try
        {
            
            Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);// kreiranje tcp socketa za poslušanje
            listener.Bind(localEndPoint); //asociiramo socket z endpoitom
            listener.Listen(10); //specificiramo koliko stvari lahko poslušamo

            Socket handler = listener.Accept(); //socket za handlanje
   
            ECDiffieHellmanCng a = new ECDiffieHellmanCng(); //generiranje para ključev
            a.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            a.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] pubkey = a.PublicKey.ToByteArray(); //javni ključ

            byte[] bpub = new byte[140];
            int bytesRec = handler.Receive(bpub);
            byte[] iv = new byte [16];
            int bytesRec1 = handler.Receive(iv); //shranimo ključ v buffer

            handler.Send(pubkey); //pošljemo svoj ključ

            byte[] symkey = a.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(bpub, CngKeyBlobFormat.EccPublicBlob)); //izračun ključa
            Console.WriteLine(Encoding.ASCII.GetString(symkey));

            byte[] msg = new byte[1048576];
            int msgb = 1;
            byte[] type = new byte [3] ;
            handler.Receive(type);
            string filetype = Encoding.ASCII.GetString(type);
            Stream dest = File.OpenWrite(@"C:\Users\JurijCerar\Projects\hibrid\Hibridno\test."+ filetype);

            while (msgb != 0) {
                msgb = handler.Receive(msg);
                if (msgb != 0)
                {
                    byte[] dec = Decrypt(msg, symkey, iv);
                    dest.Write(dec, 0, dec.Length);
                }
            }

                handler.Shutdown(SocketShutdown.Both); //prekinemo pošijanje in sprejemanje preko socketa
            handler.Close(); //zapremo socket
        }
        catch (Exception e) //err handling
        {
            Console.WriteLine(e.ToString());
        }
    }

    public static void Sender()
    {

        try
        {
            IPHostEntry host = Dns.GetHostEntry("localhost"); //nastavljanje porta
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
            
            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);// kreiranje socketa
 
            try
            {
                sender.Connect(remoteEP); //povezava na endpoint

                Console.WriteLine("Uspesno povezani na {0}", sender.RemoteEndPoint.ToString());

                ECDiffieHellmanCng b = new ECDiffieHellmanCng(); //generiranje para ključev
                b.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                b.HashAlgorithm = CngAlgorithm.Sha256;
                byte[] pubkey = b.PublicKey.ToByteArray(); //javni ključ

                sender.Send(pubkey); //pošljemo svoj ključ
                var iv = new byte[] { 0xcf, 0x5e, 0x46, 0x20, 0x45, 0x5c, 0xd7, 0x19, 0x0f, 0xcb, 0x53, 0xed, 0xe8, 0x74, 0xf1, 0xa8 };
                sender.Send(iv);

                byte[] apub = new byte[140];
                int bytesRec = sender.Receive(apub); //shranimo ključ v buffer

                Console.WriteLine(iv.Length);
                byte[] symkey = b.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(apub, CngKeyBlobFormat.EccPublicBlob));

                Console.WriteLine(Encoding.ASCII.GetString(symkey));
                Console.WriteLine("Vnesi ime datoteke: ");
                string filename = Console.ReadLine();
                string type = filename.Split('.').Last();
                sender.Send(Encoding.ASCII.GetBytes(type));
                string pathSource = @"C:\Users\JurijCerar\Projects\hibrid\Hibridno\" + filename;
                byte[] enc;

                try
                {

                    using (FileStream fsSource = new FileStream(pathSource, FileMode.Open, FileAccess.Read))
                    {

                        using (Stream source = File.OpenRead(pathSource))
                        {
                            byte[] buffer = new byte[1048576];
                            int bytesRead;
                            while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                enc = Encrypt(buffer, symkey, iv);
                                sender.Send(enc);
                            }
                        }
                    }
                }
                catch (FileNotFoundException ioEx)
                {
                    Console.WriteLine(ioEx.Message);
                }

                sender.Shutdown(SocketShutdown.Both);
                sender.Close();

            }
            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNull Napaka : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("Socket Napaka : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Nepričakovana napaka : {0}", e.ToString());
            }

        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }
}