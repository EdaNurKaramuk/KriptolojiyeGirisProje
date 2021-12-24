# RC5 Şifreleme Algoritması ile Şifreleme ve Şifre Çözme

Kriptolojiye Giriş proje ödevi kapsamında, RC5 algoritması ile şifreleme ve şifre çözmeye yönelik bir C# Windows Form uygulaması geliştirildi.

## Projeye Genel Bakış

Proje ayağa kaldırıldığında ilk açılacak ana sayfa aşağıdaki gibidir:

![Project Demo 1](https://i.hizliresim.com/r7mlpf4.png)

Sol kısımda "RC5 Hakkında" ve "Sifrele ve Coz" isimli iki adet menü bulunmaktadır. Bu menü seçimleri ile farklı ekranlar karşımıza çıkmaktadır.

"RC5 Hakkında" menüsünün içeriğinde RC5 şifreleme algoritmasıyla ilgili kısa bir bilgilendirme metni bulunmaktadır. Algoritmanın ayrıntıları proje raporunda anlatılmıştır.

![Project Demo 2](https://i.hizliresim.com/i3npw9h.png)

"Sifrele ve Coz" menüsünün içeriğinde ise bir metnin şifrelemesini ve şifre çözümlemesinin yapıldığı bir ekran karşımıza çıkmaktadır. "Şifre" butonuna tıklandığında, plain text RC5 algoritmasının prosedürlerine uygun olarak şifrelenmektedir ve Cipher Text isimli Rich Text Box'ta gösterilmektedir. "Çöz" butonuna tıklandığında ise Cipher Text isimli Rich Text Box'taki şifrelenmiş metnin çözümünü yapmaktadır. Ve çözümünü de Decrypted isimli Rich Text Box'ta göstermektedir.

![Project Demo 3](https://i.hizliresim.com/hquijsz.png)

![Project Demo 4](https://i.hizliresim.com/84cmg07.png)

Şifrelemek istediğimiz metni (plain text) kendimiz yazabildiğimiz gibi "Txt Dosyası Seç" butonu ile de .txt uzantılı bir dosya seçerek de aynı işlemleri gerçekleştirebiliriz.

![Project Demo 5](https://i.hizliresim.com/9crufd4.png)

![Project Demo 6](https://i.hizliresim.com/j7nihsg.png)

![Project Demo 7](https://i.hizliresim.com/q9o3oob.png)

![Project Demo 8](https://i.hizliresim.com/k4bu9cp.png)

```bash
pip install foobar
```

## RC5Algorithm.cs

RC5 algoritma prosedürlerini içeren dosya.



```csharp
using System;

namespace G181210061_G181210383
{

    public class RC5Algorithm
    {

        //Olası değerler 16, 32 ve 64'tür.
        const int W = 64;                            


        /*
         * R - Tur sayısını ifade eder.
         * Olası değerleri 0-255 arasındadır.
        */
        const int R = 16;                           

        //64 bit sabitler
        const UInt64 PW = 0xB7E151628AED2A6B;
        const UInt64 QW = 0x9E3779B97F4A7C15;

        UInt64[] L;                                  // Kullanıcının gizli anahtarı için kelime dizisi
        UInt64[] S;                                  // Genişletilmiş anahtar tablosu
        int t;                                       // Bayt cinsinden anahtar uzunluğu. Olası değerleri 0-255 arasıdır.
        int b;                                       // L - Kelime dizisinin boyutu
        int u;                                       
        int c;                                       

        public RC5Algorithm(byte[] key)
        {
            /*
             *  Verileri doğrudan şifrelemeden veya şifresini çözmeden önce, bir anahtar genişletme prosedürü gerçekleştirilir.
             *   Anahtar oluşturma dört aşamadan oluşur:
             *      1. Sabitlerin üretilmesi
             *      2. Anahtarı kelimelere bölmek
             *      3. Genişletilmiş anahtar tablosunu oluşturmak
             *      4. Karıştırma
            */

            // Ana değişken tanımları
            UInt64 x, y;
            int i, j, n;

            /*
              * 1. Aşama: Sabitlerin üretilmesi
              * Verilen W parametresi için iki sözde rastgele değer üretilir,
              * İki matematiksel sabit kullanarak: e (üs) ve f (Altın oran).
              * Qw = Tek ((e - 2) * 2 ^ W;
              * Pw = Tek ((f - 1) * 2 ^ W;
              * Burada Tek () en yakın tek tam sayıya yuvarlamadır.
              *
              * Algoritmaları optimize etmek için bu 2 değer önceden tanımlanmıştır (Yukarıdaki değişkenlerde var.).
            */

            /*
              * 2. Aşama: Anahtarı kelimelere bölmek
              * Bu aşamada, K [0] .. K [255] anahtarı L [0] .. L [c-1] kelime dizisine kopyalanır, burada
              * c = b / u ve u = W / 8. b, W / 8'in katı değilse, o zaman L [i] en yakın sıfır bitiyle doldurulur.
            */

            /*
              * 3. Aşama: Genişletilmiş anahtar tablosunun oluşturulması
              * Bu aşamada S [0] .. S [2 (R + 1)] genişletilmiş anahtarların tablosu oluşturulur.
            */

            /*
              *4. Aşama: Karıştırma
              * Aşağıdaki eylemler döngüsel olarak gerçekleştirilir.
            */

            u = W >> 3;
            b = key.Length;
            c = b % u > 0 ? b / u + 1 : b / u;
            L = new UInt64[c];

            for (i = b - 1; i >= 0; i--)
            {
                L[i / u] = LeftShift(L[i / u], 8) + key[i];
            }

            //t değişkeni - Tablo Boyutu
            t = 2 * (R + 1);
            S = new UInt64[t];
            S[0] = PW;
            for (i = 1; i < t; i++)
            {
                S[i] = S[i - 1] + QW;
            }

            x = y = 0;
            i = j = 0;
            n = 3 * Math.Max(t, c);

            for (int k = 0; k < n; k++)
            {
                x = S[i] = LeftShift((S[i] + x + y), 3);
                y = L[j] = LeftShift((L[j] + x + y), (int)(x + y));
                i = (i + 1) % t;
                j = (j + 1) % c;
            }
        }

        /// <summary>
        /// Kelime biti sağa kaydırılır.
        /// </summary>
        /// <param name="a">64 bitlik kelime</param>
        /// <param name="offset">offset</param>
        /// <returns></returns>
        private UInt64 RightShift(UInt64 a, int offset)
        {
            UInt64 r1, r2;
            r1 = a >> offset;
            r2 = a << (W - offset);
            return (r1 | r2);

        }

        /// <summary>
        /// Kelime biti sola kaydırılır.
        /// </summary>
        /// <param name="a">64 bitlik kelime</param>
        /// <param name="offset">offset</param>
        /// <returns></returns>
        private UInt64 LeftShift(UInt64 a, int offset)
        {
            UInt64 r1, r2;
            r1 = a << offset;
            r2 = a >> (W - offset);
            return (r1 | r2);

        }

        /// <summary>
        /// Bir kelimeyi (64 bit) 8 bayt katlama işlemi yapılır.
        /// </summary>
        /// <param name="b_array">Bayt dizisi</param>
        /// <param name="p">Konum</param>
        /// <returns></returns>
        private static UInt64 Bytes_To_UInt64(byte[] b_array, int p)
        {
            UInt64 r = 0;
            for (int i = p + 7; i > p; i--)
            {
                r |= (UInt64)b_array[i];
                r <<= 8;
            }
            r |= (UInt64)b_array[p];
            return r;
        }

        /// <summary>
        /// 8 baytlık kelime taraması (64 bit) yapılır.
        /// </summary>
        /// <param name="w_64">64 bit kelime</param>
        /// <param name="b_array">Bayt dizisi</param>
        /// <param name="p">Konum</param>
        private static void UInt64_To_Bytes(UInt64 w_64, byte[] b_array, int p)
        {
            for (int i = 0; i < 7; i++)
            {
                b_array[p + i] = (byte)(w_64 & 0xFF);
                w_64 >>= 8;
            }
            b_array[p + 7] = (byte)(w_64 & 0xFF);
        }

        /// <summary>
        /// Şifreleme işlemi yapılır.
        /// </summary>
        /// <param name="inBuffer">Şifreli veriler için giriş arabelleği (64 bit)</param>
        /// <param name="outBuffer">Çıktı arabelleği (64 bit)</param>
        public byte[] Encrypt(byte[] inBuffer)
        {
            UInt64 a = Bytes_To_UInt64(inBuffer, 0);
            UInt64 b = Bytes_To_UInt64(inBuffer, 8);

            a = a + S[0];
            b = b + S[1];

            for (int i = 1; i < R + 1; i++)
            {
                a = LeftShift((a ^ b), (int)b) + S[2 * i];
                b = LeftShift((b ^ a), (int)a) + S[2 * i + 1];
            }

            UInt64_To_Bytes(a, inBuffer, 0);
            UInt64_To_Bytes(b, inBuffer, 8);
            return inBuffer;
        }

        /// <summary>
        /// Şifre çözme işlemi yapılır.
        /// </summary>
        /// <param name="inBuffer">Şifreli veriler için giriş arabelleği (64 bit)</param>
        /// <param name="outBuffer">Çıktı arabelleği (64 bit)</param>
        public byte[] Decrypt(byte[] inBuffer)
        {

            UInt64 a = Bytes_To_UInt64(inBuffer, 0);
            UInt64 b = Bytes_To_UInt64(inBuffer, 8);

            for (int i = R; i > 0; i--)
            {
                b = RightShift((b - S[2 * i + 1]), (int)a) ^ a;
                a = RightShift((a - S[2 * i]), (int)b) ^ b;
            }

            b = b - S[1];
            a = a - S[0];

            UInt64_To_Bytes(a, inBuffer, 0);
            UInt64_To_Bytes(b, inBuffer, 8);

            return inBuffer;
        }
    }
}

```
## License
[MIT](https://choosealicense.com/licenses/mit/)
