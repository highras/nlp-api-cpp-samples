#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <iomanip>
#include <memory.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <vector>

using namespace std;

const string HOST = "isafe.ilivedata.com";
const string URI = "/api/v1/image/check";
const string endpoint_url = "https://isafe.ilivedata.com/api/v1/image/check";
const string PROJECT_ID = "YOUR_PROJECT_ID_GOES_HERE";
const string SECRET_KEY = "YOUR_SECRET_KEY_GOES_HERE";

string getUtcTime()
{
    time_t result = time(NULL);
    struct tm utc_tm;
    char sDestTime[512];
    gmtime_r(&result, &utc_tm);
    strftime(sDestTime, 512, "%Y-%m-%dT%H:%M:%SZ", &utc_tm);
    return string(sDestTime);
}

unsigned char toHex(unsigned char x)
{
    return  x > 9 ? x + 55 : x + 48;
}

string urlEncode(const string& str)
{
    string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++)
    {
        if (isalnum((unsigned char)str[i]) ||
            (str[i] == '-') ||
            (str[i] == '_') ||
            (str[i] == '.') ||
            (str[i] == '~'))
            strTemp += str[i];
        else
        {
            strTemp += '%';
            strTemp += toHex((unsigned char)str[i] >> 4);
            strTemp += toHex((unsigned char)str[i] % 16);
        }
    }
    return strTemp;
}

string createSign(const string &data, const string &key)
{
    // HMAC-SHA256
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int length = 0;
    HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char *)((char *)data.c_str()), data.length(), digest, &length);
    return string((char *)digest, length);
}

static const std::string BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

string base64Encode(const string &data)
{
    unsigned char const *bytesToEncode = reinterpret_cast<const unsigned char *>(data.c_str());
    unsigned int inLen = data.length();

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (inLen--)
    {
        charArray3[i++] = *(bytesToEncode++);
        if (i == 3)
        {
            charArray4[0] = (charArray3[0] & 0xfc) >> 2;
            charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
            charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
            charArray4[3] = charArray3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += BASE64_CHARS[charArray4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            charArray3[j] = '\0';

        charArray4[0] = (charArray3[0] & 0xfc) >> 2;
        charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
        charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += BASE64_CHARS[charArray4[j]];

        while ((i++ < 3))
            ret += '=';
    }
    return ret;
}

size_t onWriteData(void *buffer, size_t size, size_t nmemb, void *lpVoid)
{
    std::string *str = dynamic_cast<std::string *>((std::string *)lpVoid);
    if (NULL == str || NULL == buffer)
        return -1;

    char *pData = (char *)buffer;
    str->append(pData, size * nmemb);
    return nmemb;
}

bool sendHttpRequest(const string &sign, const string &body, const string &notime, string &response)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        cout << "curl init fail" << endl;
        return false;
    }

    vector<string> headers{"Content-type:application/json", "Authorization:" + sign, "X-TimeStamp:" + notime, "Host:" + HOST, "Connection:keep-alive", "X-AppId:" + PROJECT_ID};
    struct curl_slist *headerList = NULL;
    for (auto key : headers)
        headerList = curl_slist_append(headerList, key.c_str());

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, endpoint_url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, onWriteData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headerList);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        cout << "curl request fail: " << curl_easy_strerror(res) << endl;
        return false;
    }

    return true;
}

string sha256(const std::string str)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    const char *string = str.c_str();

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(digest, &ctx);

    char mdString[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);
    return mdString;
}

string check(const string &image, int type, const string &userId)
{
    std::stringstream jsonBody;
    jsonBody << "{";

    //-- sBase
    jsonBody << "\"image\":\"" << image << "\",";
    jsonBody << "\"type\":\"" << type << "\",";
    jsonBody << "\"userId\":\"" << userId << "\"}";

    stringstream stringToSign;
    stringToSign << "POST\n"
                 << HOST << "\n"
                 << URI << "\n";

    stringToSign << sha256(jsonBody.str()) << "\n";
    stringToSign << "X-AppId:" << PROJECT_ID << "\n";
    string timenow = getUtcTime();
    stringToSign << "X-TimeStamp:" << timenow;
    cout << stringToSign.str() << endl;

    string sign = createSign(stringToSign.str(), SECRET_KEY);
    sign = base64Encode(sign);

    string response;
    if (!sendHttpRequest(sign, jsonBody.str(), timenow, response))
        cout << "translate fail" << endl;

    return response;
}

// g++ -o translate translate.cpp -lcrypto -lcurl
int main(int argc, char *argv[])
{
    string imageData = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxMTEhUTEhMWFhUXGCAbFxgYGBgfGxoeHR0YFx0YGx4dICggGR0lHxgdITEhJSotLi4uGx8zODMtNygtLisBCgoKDg0OGxAQGzAlICYtLS0vMi0rLS01LS0tLS0tLTUtLS0tLSstLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLf/AABEIAKMBNgMBIgACEQEDEQH/xAAbAAABBQEBAAAAAAAAAAAAAAAEAAIDBQYBB//EAEMQAAIBAgQDBgQEBQMBBgcAAAECAwARBBIhMQUiQRMyUWFxgQZyscEjQpGhFDNS0fAHYoKiFlNzkuHxFSRDY7LC0v/EABoBAAMBAQEBAAAAAAAAAAAAAAECAwQFAAb/xAAzEQACAQMEAAMGBQQDAQAAAAAAAQIDESEEEjFBIlFxBRMyYYGRFCNCsfAzQ1LBJCWCFf/aAAwDAQACEQMRAD8A9Ct/+I+tOlpo/wD1+9Okrks0gWI7o9BSY6iliO7byrjHaosoiDCnlHqfrTcNvJ8xpYfuj5j9a5hzzSfNSMI+I971+1OHeFRxbv6j6U78woBHt3hUWI7w9qkc8wqKbvD/ADrQkDsfiO4/pRLnT/j9qHnHI/pU529vtRjweZDFsPQfSug8opkbco9B9KLwOCaQX7qDdjtYb2oQjfCA2kBxozMVQEk20FWpgigGbEOCbfy11Pv4/SqzGfEaRXiwo6c0x+oHWqPCYTtXYhmLkXd2F7D/AHMToKtFRhjlitOXOEXc/wAWM90hXshspIFz7dKAjiklJIzTsDrke5U+jd0HxH0pRyxoTzdtcEXY5YR6MRmf1GlOhmmnBUEIiC5VLLELbkgczD3rzbb8TClbglbBRxC0sig7lQTI/vY5VoiA8uaKC9vzStYEeYGg8aBwmISC6sqSf7kPL5gaHXbehMSWklbshHEAAZGZmyR32Mh05iNoxq3pdq9FOTtFAfmw3ETSk5ZAqBTcKttSdmY9dNB71yFyGDAXt02BB0Iv5i9QMuHgS8rYye/5sjQR38U5kkI8i7UBJx3Dg2XDpp1eFZD+ry3P61o/BTvdsXf5IvEjYi7KnvNf27m9RAkbAj0ysLeo/tVJF8QKht/C4Vl3uMMsbA+OjMB661Yf9rFU5hCQhGojC6HxBJC/qtLPRy6YVL5BHYZzZHjPhcnP8uQ6n0FDwY54GtHJIG/oZWA91PSlgcZh8QxCzXY92KUdmxOwCuCVJ9G9qnXGyKCrOMoNjHJr+j7gVCVN03aWB73LfC/EauMuLhy/7x3bePiKIxHCAy58O4kUm9rj9jWdEMLNZXdHtyxu4s3yvsfQ/rU2DnkwzHswym+qsDlPkfD1oOS/UK4/4hiNrY3uDqLftUbbp8/2NXGHxEOMXTkmA26+39QqqxMLRuquLEN7EWO3lU5U7ZQ0Z9M7jP5be31FSsaixfcb2+oqUilyMRTHmX3rse/tTZBqtOTf2oBIpe8vzVMetQzd5fmqeieBH2i+b70XDsfmP2oWTQR/P96Jjbe39RpkAeh39ftSpm9/Wu0QFj//ACfrXXOlcO49D9aTHatTJpAc/d9qTdKWIPJ7UvCovkdA2FPKPnP1NNi78nrXYO6PnNcj78nqPpSMI6LdvanKeYU2PdvaujcUoR8neHrUWI3H+dalc6imTjUV5nkPnvlb0qUnT/jUMq8rehozh2G7U5dlA5j9qaEW8CSZHw/Chl7SQhY1F2J2NrUFxviLyjJGciLr2drE+GYjS5H5aZxvi/asI4rLBGeX/cV0z/KOg6nWgcEQT42O19/Mn9yfS1M/D4YgSfLI8HhzbMziwOoVQXJ/pAO5030HjVkcPmUCV1hjOvZi5YnxYLrfTr4bVC0hBKrlvtZOnj6KN/P1qv4nJFGl2d777nm/XWgmuEPZyYRJxCKIlUVHtu8iEn0AJsLCw0qo4nxlLliQrHTKiWHraqjE42SSyqSqDYDrUUGDA13PnVdvma6elbL74cxGKxMgigbsYlGaWQ5eVer2OhbSwv530Bp/GfiqBR2eFkkIUmxi5VJNru0pUySMbasMgI8RY0Xw6OGPh8nbK0hxEojSFL3mKjMI9NQt7lrflBrB8d4nMzmNyqlOUiMKqp/9tAuigG9zfU7k10tPCMY3sYtR/Ua6QzGY4xsSWvIx7zP9jq2+5qukxD94uTfqGJv5aG3tQxiN+vsP8vVzw34SxMwukbAEd4i1/Ig71SU0uSSTfBXQ8bdDdWN/Mmuv8QOdwL+NvvuP1rTR/wClmKbU2A+n70NxH/TXFIQFAa/hfSpurDzDtkUEHFwT/Sevn72zA+F8wr1KLjpeGKQnR+VrgaON/ZhzD/l4ViZv9MsYBcBT5A7Vqfh3gDNhZ4JVkWRe7axtIgzKLbqSCQL6ENob1KrGNWNkNFOL8RcK2HsUdZFb83c/UDwO9cgidmZYzJLGLWN7OvopOo8qx+C4i0ZAlXtFG1zYjyv4VsI5InXtIFyMRewc67g77kb7iufKNjRKm4j8Jw4l1YSEqTdWGhv/AE3Ngp9a0H8QJ7RTDK+8bk6kjcHwYHdfrVDDP2alw5b/AL2Fls3zKRuR51ZyOjxhgSyHVWG+nUeEif8AUND0owWCE2wfiClcyMLMLfUajyNSk0cVOJhyMR2yi6MNnXoR5G23Q1XE230I3qVSNsrgaMjkm4pJv7UmOorib+1THGSd5fWph1qKQcy+tSEWBpkAEl7sfz/ejIz3vmP2oSbup8/3ouId75j9qKAdTc+30pUlOp9vpSprHixbf2NcJ0FOO/sa50HpWlk0Bzjk9qXhXZ+5TCNqixkQwnl/5n+9cTvye30pQ7H5jXE/mP6CkYx2PvN7U6/MKYneb0rv5hSXCOfcU2Tf2p0h1psh1HpRYB6jNoNb/rRfxLP2UQgiGVnGZyLaLoCPf+9N4Il2MjMVROY28BrY1n+IzmSYyXzM57ttFHQW6m1h61aL2wv2xOZEbYdmQspBVSM1tACdAL9ftRK4SNEu092OuWPW3jc7C3hUq8IeQ2LhSoPZJYDMR39uu4v5VV4+EwgmUjKpsAPzEdPSk22KLxOyIsfxBYkKg3Nt7ak9daz7FpWzuSfLwpXMjZm9h0FEqtUS2I6dDTpK7GxpUgFTPh2Cq5HKxIU+JXcfvUVqVtmyNuiz43xNosJBDEREOyaWadr8iyPIFjjA1aSQoRYEWVT0uR5vhl1vb9fD0Gw/QVq/9RYXMeBUZ+zWDMxKtkVnYm+bYsddOgt/VWOaNkOW+h/zWutCVoo+anffJ/Nmq+EeGpJOpksVFjbodth4eule2qFVQVF7jQAf5b3ryH4IwzHn/KOvifv/AOtetYaUKgDeGt/IVmqSvNlVF7Ux+dzsAPUkn9gaEbGm9iQPXMPqtV+N45JE+ZBHInWMAq1vENc3PqBSw3xlh5XEd3jfbI6/fwqSz2es10XcEynqL/rVB8V4fs8ZhsVHm5/w3yaEkarps2hOh3ygaURjfiuLD6yXI2FranXT9jQnEOKHiGHZeyaLLzo17kFfIa6jNr/eq05pR5FnCW7gxfGsLlmcXvrcG1rhuYHXyNAYScwNmGq9Rr+tXXHyTO2a98q3v1sign9Qaq3Ssrd20duNNTpK/kaDAzRSczBjm1urajxIuCDejZ8MsfLHKDG1mIP5ehYjp52rHYSUxsAScpO4O3nWwhwkQXMz9q2+TVbg6XBGlxvU5Rtg5lanseRuGdkkVo27t8ua9td/VetaTGTJNGJFsp13NjfqPQ9KzZWNlaONnvlugYjpunkbbEb2qfgkqrIFaMkSC13FzcXF9enj6UEnazINdhGa4FPjOvtUUsXZkoeh09KfGdfao8MZcHJjzr61K3WoZhzL61NRueA5u6nz/ei4z3vmP2oSfur89Fp+b5jRR4QBufalSj3b2pUQFo3eHvTOg9Ke3eHqfoKYDoK1MmgaXu0y+g9qlnHLTD0qTHQNHsfmNcXvv6D6GnxjQ/MaaBzt6CkYTid4+lOtqK4nePpXeo9aRYCdYa1HKdfY1Ix1NNhTM6rrqbUbXdgXCsZKIMIA28h8thrWfjxOQ3AIzA5LaWv+f/dbW3rVjx3HM8zIOZRyLoLC29/cdfAVVxSLm5wHsCCSTfxJ8b32qs2t1l0eirK7JDGupWRr25QRzejG9h7VnOJ4ppGCk3C1Y8TdACYwVG1iSTfxPrVPDH18a9BWybtLSu7kiWrQ4D4WlmUMksBB2/EufewNjVBao8PgM0qZTlLOBcabm1PG18myv7xRvB2sb+PgLHDnCuVRkYOH/KDsdT0IJ/SsxxXDYaEWGK7WTosaG3qWvYUZxL4hjw+KMXfhU2KMS23W52IO3ShfiPAxLLnhOaOYdovhrvbyv06XI6UWsO6MGmdRzs3a+QyWJiHZpCsIOREOqWH+3bb61nOJfC4ZRNDqh6WPXQH012rX8NwgxMEVxcIxElzpoANfUBW9DWjwWDjERiUXAI6eOul+n9qWipp3uGtOHwtGX4FhOzjjS3hf/P1qz4skxHKM3kCt/a5A/emzLlbTpWhweKVluLH6injHc8k5S28IyUvxHLHkihwLAMQDJIyoq9CxFndv/L6X0qvx+GkknVpIlvGcwcXsw0NxdVPW1io9612MhkZrwOLnexOnncae29DPgVDqskhux1Jvmc+nRRTTzhISFk73KP4pwsqmNoURuXMubRb7XJ6aHpV78OHESdlnVGAS0j2yAMRsiksXHncdNKvcdgEeIgi+Uae3QVX/AA5gkRhIjFwRptpe2vnVFDbJKwk6inBvtFDxfC4QfiYiV1YaER6+OhNjrWQx+OwpIEHaBbHmlKgttsB0H3rQ43HJMuOw53WR5EB65HJNvEWvVPwklWYq+Q9k2uYqPyDUg6b+F/Aqdai1FYZooyqQpud+OipMyNoGU38D6/2qx4NPrle9h52v4EVZcVxOeNgsmdC40zk2LMZRpsBaMi9z5WFxVDmykN4b0js1gtCUtRTcmjZYZIQboGLoM6vvfQXR18OgI8aDaKRo+Rs8Z1KjUxm9tQdRr1GlG8DxUYsOVX3SW2x6BvKmyYpnkkKIqkC7WAI6hiD3gCbnTxpejn5TsFzEvBFIe8vIx9O6fK4pkZ5vahfh0nPJC2naroLiwcaqffbTyqTDNzWPQGp1Fwzyw7E83eX1qZhUUneX1qdqRBAcRsvzfei0/N8xoWYcq/NRkX5vmP2oo8xq7m/lSrqbnfp9KVMeLQ973+1M6D/PGnHve/2poGlaWSQPL3T70wd1afKOU+9RJ3V9BUnyOiKP83zGkf5h+UVxPzfNXCfxCP8AaKmwnR3j6Ur7etcvzEeVO8KXs8xMdTTsDIVYuNMisb2vbS23vUMzb1G38iVtNSgHubn9hTR+ID4AGwwYkLKXY8xBFixHW996hnwbHuNmYm7bk+Z86jbXy86IweFDNdZDlUc5GhHkvjfYV7LZRg2P4UDhmnuwAZQoP5ujHxtfSqZRar/4gxpePUWXMqoOigXY+p0Fz41Qiq3xg6ehT2ZEtdBIN1NiNj4VynClNrV1YHjwu/W+58amhQqAtzlBJAvoL72HS9OrtqO5tCqnFcFrwHij4Vs5DGGUWYAX5h3WW5AvqQR1GX+mtbwviSzxPJGjrlfKc5UluVXvykjZ7W6Gsh8KzzrP2cSdqj9+Nu78xJ7p862eDWKKSWCMKM34tlNwCOzQr/03/wCVaIRurnH1TSq2tkCxTg61Pw7Bg2drW8Kr8UbEjpfSo/8A4gyC2hHS/T+9Zo1Enko4NrBpsVxRIl9BoBWNwvGpIp2nmjaQSLyBQTksTdfK/LUPEcS3fYMw8gST5ACooviZVGVo5Abf921/pWmMnPII0Yxx2XHD/jZQWTI6tfRGGut9Bbe9unnVhwKZhiCpUIDzhQdALXNvLfSsrh/iaLOWWOQyaDLlNyBe19L9T+tXuL4sDBJMBldl7NR1XPv7hRf1NUkni7FnBLCXODH4kBpGcaXZiPck/elmdVldDIpSJ2DRsVIIAI2bm2OmVgbG4G9ctU+AJ7QZMmcghe0Dsuo5uVSL8gbmJsov41mjK8rm3VxSoO3yCOKw20WYsqyMMryYl2uoAbvv2emcHb0quDWIawNiDY7Gx2NF42GyqSUILlgVOJ7zojtcu5BuuU5W6BiNjQkg0ozw1kloEnSZqJcJE6iZQQpNnAIXJfW4O1j5jelDDCJI2jkK81mZ99tTppr5U/gVhBG5s6MDHKv0B87bHyFDY7B9ixXKWUEMsov3TsPAdfepvGTnyXiaDw+EjYZBK7I1w97bfa9S49QMUSvddA499x+t6oWGpq9lfMuGPgki36aFaF9yf3Ftawpzqo86mI/z/PWoJt19RRDio9BBJ15B81FJ+b5j9qGxB5B81ER/m+b7Cijw6Pc+30pVyPdvb70qICzYc3uPoaZfT3NSMdfcfeoxt7mtciaIX2Pqahj7q+lTNsahjPKKhIdEKfn+akD+J/w+9JDrJ832ppb8QfJShOnve1dFRk8w9KetqTsJDijvQ84thwfGT9lH92qTF/mqJmIiiawsM1wbXILZffu0V2eA8Ph2d8irdr907ep8rVbyR5isKEWFy76WO139ANAetNcrEnZxg9pIBe/eVTtGPM3t5D1qLEkpbDx2MjH8U+muQf7V3Piaqoqwrd2VXxTiUJjRBYLqF62/qbzJ1qmAqfieCK4qVBdm7QgdWO1tvLpR78BkjjMuIaPDxjXNK1jproouSfKn2SeEdejOFKmtzsVdKpeN4jD4S3aCeUMLrIiqsLg9Vk57/peqPh3xLPNMy4aHDWXYMfxG817XNn8wE0/erQ0k5k6ntKlFYyXUYJ7oJPkL/Si4+FzsQFibMQSFOVWYC1yA5XTUeWoqlnxGNndWY4mOI51Z4MQoQk2CKFvYag7a66DltQfwhimg4nG+eVkVcsn8QojkCSXW9ibsqlVYtpsdNRVvwKSu2ZH7Wk8RRvvhHHqJEjgMcjsFaU57IoYOQWfKTIAENggCX3ZqyHD+OFeIT5mCiWd2hkWwQhWeIMo8DlIYHffretD8F8FPCjxJ5GVYuURO0gVsnMwIzAqws4HXmRhY6VmOBYDD4yLEpLID2UxEcqiNHA/JLZDls217WOm/Ss1GNPHBhjUlKpufJvEx6zHKbLIRqt9G/wByHr6b/WqviZZGsw06H7Vj48e8DDD4w9T2M691rHKfRgRYqdQa2GFx5ZMs1nXbMf7jb3rmzpWeTp06qawOwsoZgTsOlEcTgeSwQKB42BPtfQfvVVPAVN0D2+Un/qS4orB8WdN1JHv9qCjK+CrmuQ3gvA3Egztf9LDxO3hS4pD2+HhmieFMM1zHmcJdicupfvNYfpQPxPx12gWCAETYr8IEgjKp75HXbQt0qPhcyw4s4eZs2Fx6CGNRk/CMYCLox1Vge9bcrW2nTUlaXLMNXUzjPcujs3w/iVuTCxHilmH/AEk0Aj5SQUU5lKkOt+U2upB6GwuPKgYOH4mDhuOjSR+1XEoAEc9ohjZYirMpGuTKRY6gjbaosP8AGOLSNry4fFkAXgkidnuSAQGJ7QlQTckAaHevPRXvtY//ANJuNqkbouMXig2ayRDNkzFUyklFAFz1sbgX2GlCNRoxuDkRZJBPhCVBa8EjxLprcgXjAPidv2J/7PyuueBo8Qn9ULq36jQis89PUh0bNNqtPt2xdhfDHEFUtE98j963h4jzB1rQy4UnNh3IzDWNr8rA6+4b9m9ay/DcI6zFHRkJUjmBB6a61psJN2inDs34kZ/Cc6A3/L42bp/6Cp2zZmTVpe8uigxCkMw2ymxBq6hF4Yj1EjL/AOZAbftU2KhMwMmX8VDzqRY32zW8ahhcCLLvaVTcjW5Rr/T61O1m18iLdyTEnWP1ohr0JiDrH60UTvUzwNP3B81FJ+b5vsKCxHcHzUXF+b5vsK8jw6HvN6D70qUPeb0H3pUyQCwbvfp964DofU1xjr+n1rvj61pEIW2PrQ8XdFTnr6/YUPCeUVJjIji3k9R9Ka3fX5DXYzzSe1cbvp8ppAiYc3sa4KTDmHoaSmp9hB8Xu1MwTARiR/ygqoOxOYtf5V0PmafjWtmpmKARtdcoARbeA1Y+9/XfpTxPCnkMCmZye1bVb7rfQsfBjsB5+VAcOifObAljbMB+UX0UeOpqGV+1YsdRY+l/GrLA4oxqZ5DfKPwUA0uARnI3IHTx9r1aK3OwVFvgp/jniTripocEWVr3xMyDnBIH4SEaooAuzDqbX0qn+H8RMCqAg4dmIdJQZI5WuMwO5MhHMDuStgTQ+Hi/iJWCGzPoLKebNqWe3ifW2YaWBrdcH4FNAvZBhl3BXLcXC3RWzcuue/iH5SpvVa2rjTwnYecFTVmrsxXGsPPgM0mCkJwzayYeRc4izE8rxsOaM7B7A6WOu8PDcTDiLiXhELsoDFsJMYnO1mCA2bXwOlei4bhkUYcKi84Idbkob75htrsbeNzrXknxBwhsHN2uHLdkG5WubxMb/hMfQWDHvDzuKrpdVS1F4p+IwzpuOWsGmthSSxfi0Fwb9rCmITSwJPK17eJ1oaThMOKeJE4tCxVvw4jhWhk13VbAEEjpa19bVVf9uscACgjUBv5nZXscpHMScut7nT0tVjwDjUMksYeVpiWu0cq5yJABzRsU7OHKb93MpH5diNkd8fiItR6PSo+Hwtw7EYaSdViYslzMjGIaKFYyKCHBF8ragm1wALeVNFFglMAxEaYtXLxYhMjQypoRHKVJNrjuuvKcuttTscBglPBMamaRVzvJIxhUWBIkN0kVSbLa+XT+k9B56rSKBEowxw7XUTthWVI89ozMzMgKsQyi92A5etjTtXPRwXPD+MRYyJExUuHIkLiWKxR1YaQtCblWJ6tcDxJtTpI/4SASwYtcRGuhViASdRYMLqpsO64ubW8qjw/wjhFQvBiRLpYGSJZI7i9zyi9rC11Jsdbm1hWy4/DAIq4USlWYMVHYQyZcrKuVCXlKlDlLHUubjoIbISfh48rFlOUSz4b8XdoCYcNiNBdjGAyjcm9tBt5Uofj9867RqT35VuBpuVS7N6C24pnCsFLPjmKhCXGsRLGOEZbK8lrKzhBcKttbaqKtuI/BjxKYgi4qNLlFJKuhOt8qkLINb236ajSoznQpySk7N/MqqlWSAYfiGB+0kGJviHsrSyowJW4GSNFB7OMDWwBPU1XYTG9piyC5nEZYYZBFrM7sFUoj3VWAIa7AgBNjvVjxHhHb3ZUwuS5zERuHhubrGwQo0WW9gHVRbcnU1U4jgT4NDKjQzxlgblLMNLcpvcXzHUHz3BtphsvbtkJbmrnp3xpwqeWFRHApd4jJJOix5O3Xs1tqdnAZcxubWrG4LgmKw9zip8BBmbMzzTsZSR3QyxOM1rWC3sKtppVlwWIMREfYSw4kCzkiN0QtqhYIp1GU3sFN7AjLkeHYXhoxaYcQS4pkzgGNQ6yXzEMyLznLsBe217a3o7pE/ix0aRo8POCHnxmP6smFh7CFuozyNbPoNCWO2lVk3H8TDI+DwGGiwMvJYRoZJnDWJLyt3bKbk23Nr9asMWmIifK+MWKOwyYfsoe3WylSqqrGOBbXIZ3Fuuxvb4PEwwJmw6LLOxLtIWDliQeaaQsolPXKtlF7C9hUJVNuZFFDGCw4ZDiMPd8djZJYmJESOodpdASAhW/icwIA8xrTcZ2byyLCSk8Opie5zRkhg0bfmUgg23BsKbDiJcQlmxJzMCDmQABrEjs2tlk13CsRoaBxUU+WPExtbEwMQzMFUvGGIzOoOUAbkeBPlWCpqIuSUkaqdO6wy/jxhkH8QmroB2y/1LsH8z0Psag4i34iFASrtnY2taysBp4G591NAYPiaSMZ8OQsg1nhuDbYM6W0eI9bbXv6SzugeMxtYOe5fVCLkr5gbg+BpaiaCo2dgvEbx/MKLag8QdY/mFGGszCB4r+X/wAh9aLgHe+b7ChsT3P+X3oqI975vsteieO4fvt6D70qbD329B96VOgB4a/6D61IPzev2oOF7/p9xRQ3b1+1abnpx2uxAw73rUMXdH+dTU5HeoeHuj3+pqMgIhjHNJ6D70n78foa7G3PJ6D701u9H7/SkCJ+8PeuXrj3zj1NdFIwgnEj3vQVSQ43NKFa5sSZCT9/GrnigOvoKEbBR4O+IxJHaE3ji3y36sOraXC9Nz5Xpw3DQu3ZBmNljhQST2U7IAO/poWAGgP6nyGtY7is2IxKifJZCpYkMLAA5Gvci2q6D9PChuP8TbEOGOuniTbx+ntXoHAMDHPgmYItuyAj7QDKdMrOyDRrEkXI1ynob1a21Y4Nso/hop9srfgXAFImcowdtwVIsLaAEi5v+161naWBJuLb3tp6+ArK4Lgz9q2ZpChCiJoSqJ2euYPawBN9cq36gi5tN8TthxAcMuVmVgArSLytYsELO4szA2A1NjsBqPnq2njqdSkpXv5dIhVnGOZMt48VHNfs5Ee24VgT722FZ6RljlmSQAhojcEA3AJN7H5v1A61B8N4OKORWVJklIMb9opFtFItqVufPrm2tahfi+GXPmysSqvlkYRqMtlLCyatpca2+tW02mjS1DpqdlbvDFqzSXhygH4b+GleFZlWUMylroSVIZTeN0uCbA7g3B8dqKl+B8YEXscTMuVRkXMrIttQLMY8mttcrH1rT/6dxBcJGNdBrfyQD7UZxdsT2arhWjVibEvvtpl0IvodxWmp7UrRrbE1a75Ie4iyl+CPhXEphcfDjrv245WciQWysATZiwNyG8stZPgfwXh5Y1Rp3lksM0aYvDqhI10Ch2Ive2YAjyr1DhGHxQ/i+0IkzJ+Fe6C5DWS8YJCi4Fzrpe1jVXwnh7wg4jGpAXTRTGCTEhYZrs2jWvctYGw3NdmWrhCipTfifCXbMzpvfaJSn4Ogw6rmhRANFBOJxVtr2RBGgJ87jXrT8Bj8CiMAmJYRnniWFIAoPLqiBGdTfuksTetmnEQZ2hUA5UV3a+gzlgoFtzyEk6aWte+kMHFc8pRSLKxWwzM5tdCxAFolzAjM2+U23rkx9oVmnvjxnDKSovphfCosOkKiGHsFIvlVAu/9S/1UzFcKwzujkzBkNxlkKi/mAbH3olbnQa+lSGA66r+v+eFYVqNRUk5xjf1RRJRVrlB8UcPSZ4zG0MLDTtCSJvEZGDDTTum4NYXiGBeYtFJHFPKozMRGc5JuoyvCVZk8HKEEjU6V6jjsIrjJKiuPBlDD11BFZzGYrCcPIyYYgyHeNBbcrlzEgAjYKK36b2nOMfduN5dYsI6G53iyH4S+GWIkaYGPPhf4cxG9iF0DHUnYbHx9qEwPwLKFKSYzKmb+XholhQHzym7H5rjyq94N8XQyTJGVkjLsVXNprZTa4vuGBB286lPCYknFiymMMygSHUMxZs2uZ1BY6Wyi/U7Wlqa8qW5va/S4vu4wklI8z4/wAQCfDxSxOxjJZivOo5QI7lsudrjRBe1idNtJwrDxwYk5SZJHYAqtgI0UWDN0HKBpuak+Pyz4dsQOymw6ldEViwAZTnYhrHIQ2hGl+lzcLhWNukZS1mGa40uWA5j6+NNrKrlp4vvv1+ZXSu8pXNkcFExLWQlu9e1+hGrbgeulh4VUoypMXaRiAMgBObMp5iNNhsov4dTerLASRBezzozAXKh1zeO1clEez4Z7eKsv2H1rg0qs9zvi/my7gkzEcb4OcNiIp8OwWGR80MhJsrHUxvbaxBHoT51Y4fCvJJBKMoZQzSxqwO4FpUtuhvqN1JHSxGqwnBcNOjw9oxjexMb2DIw2dSNiNtiD51k+JfDb4BO2WRzNEcwLHQLdl5FXWzXW99LBvQ/Rp7oJvs8pRqeFuz6+Zd4neP5qMkqtwvEIsQIgskf8RYM6ISVNtTlO2a1zk8iRpVi9Zpx2kndOzBMT/L/5D60ZF+b5vsKExekXuPrRcQ73r9hSo8cw5529B96Vdw4/Eb5R96VMgEWHksLeFWl9W/zpVK2j+tWuHkuD6D6VoZWvHFzl9W/zpQ8XdHqanO59B96gh7vufrUpEUQx99/lH3psp1j9T9Kco/Ef5RXJf/p/N9qmEUp5l9T9KROhp0iEugAJJbQdetR8X4ouDS6r2kxNh1C/KLEtbq1janhSc38gxTk7I7xXGw4VVlma8hHIgF7edup8L6CsN8S8ejxIW0bZgSc7GzC5F9ASGBA6i46GpMRw3F4mdnljaSwHcDHfQZet76nPYjrbQVb8L/08klhRpEeCS/NzKwZfErflY7Cxt1I6Vqslwb6ao0bOTyVPw58NHEyxplPZ/ncEAADvDxvtttet3xnGoEnwkRQuqqqwKVViuaPkP5rFGsTsASazHEM3D8G6QTANJiD2baB2jiAZkBG93BXQa66C+m0xhlMy4i0QgeNCG5hIpbvBrixXVToQdDoalqW4Ut65WbeZm1Ff3lXPHRR4ziZwseeVxJinHLAJlVbsdFUMQAo2zEXNj1NB8M4wcRikIGUrH+IEQtZw20jNYqQA6gWuM5877Mqn9Vwf9v8Aciq7FTrDICt7N0AGh3Bt964FPUwhFrb43e7uuPJJdCbd0nuyugczmeBmylStyAbE3Um219yCPZvCsv8AFspaTNmuhwzkLYWF8tz6m49LaVqVcZmymwW6sDYADe/gBsfQm40FsJx2YO0mV72w7JobrfOAPqNfKraelTVb8vhfXktG9nc23wYlsJD/AOHf9qrviCDFl17KbkOyCNOUW5mkLMCw6AqQRc6dRfcIGWFB4IB+w0qrm4zEMUsDPZsttjlDGxCFtgSNbX/SpU6k1qd0I7ub4ITpe8i1cv8AgZIjlMjplJumrLZbWsTnftDcE3zHe1DTcJOYMs0kYBJC6Ml7WIIILZTfuhgLgEWqy4K5y2GdiRdiAAxI0YkMdLm+l9KjmmspLCyLrcE6WBv66eo/SupqajnCNSOOUZqacHtMaivgIMUWuJCMuHcKzR5QpEUYHN2eVmYWc21GpFaHDtHFH+HZGezMX3MjC4ErbhjcC58LDYCovimOX8KaGPtDBJ2mTZihRozl8wHvbqRaoOHSGfCiUSLI0q3cAKycwsUKNYZRtzEHe5NLCMajUpdvPr0Wqt7LoLTiTKzyWYRk3xCuyg4dgLZ+YjNEQoIyX1zb9LMS3HKQR0Iselxt61S8B4eEZy1tR2ZR9dDZgqhixAIvyZmFrEbWByYlEzgwMFRbowUESAGxtsc2Y3ObQ5gwYi5F9ZBT8NPDX2M9NtZY3H46QKyxoRa5eR8vZRqtiXLXOU26HXrY6Xi4JiTJCGFwGzFGdbFrkkNkOoFiG18bbClxjByPh5I4lERkOaVG1Nwo0BFwTyqOq71XpjeyVXCsczZe7IzOcrZRcksSSOoCgX20satOE6O2K8S8/MaKlu9Sz4LgOwEaE9o2pzmwNzcsFW1kW/5QbdLUXxrhwkkIYOARzMsjxte2VbdmwB0Zv0FAnNBCjfmWPYkXLZSdB15jsP2F6h+N+JfwzYaTOioHOdbczCwuEB7zWPdGpuLbGlpbpU24PP8AvJ7beW18EcvCcLhI8Q2SQxy/zY1uwN7gkKBy3B1PufGvOvhLBAYifh8sZKK7EAtlcpup1NiQMux9jXpHGsRMVRopOxRxYkx3dT3hodASARqPK9yLZeAZeNKC7SGXDMczqoJZQrgWVQpsoH96hQnUnSnvd5NX+xVLY1tx8xvGuEYfDRKqpJJzWyHNZswI1yAAm4FgetupFy+AcSw00Sw8yyhSxCNKEGyrdlaxIATck3HjetHw93dSEuT9Nf7a+X6Vn8ZA+FnxDQxkh1UligK3FycoBUaXy33Om+U1CnUqVqPu54kspt2v/PIpNfmbk+eSH/4TICXik7KQtmjjuGWRggz537xLZSQSQdCSNxWkxOFbHYUxv+HMIiEJYFrkZXjkCkhhoDcfsVrJNwz+JhE+FWSOQFWkjykB2BDHsy5ABBzWINjcg6GmHGTYeXt8QHjuwaOLMLsVAGY5ep0BF7W3rVpqz3Wvfpq2f53ctUiueLFEyTYYZbWZtbobnlN73BzCxGhFuvhW5+F8Z2+HDs34mobVQpK36XAjJuu9lO9lza1nHY8OyDGxI4GIF1C3DZjcSRsqnXL/ADNPDwFZ/BwznshefkIsgDgoG0RlAGgPVxsGG5vW2SbujRLbqKalwzeY0WjYaaHX6/Sx9LHY0THuw8/sP7VQ/DmFxpjS+HDx5mBEgxCyFbt+dhbKSbgEWvY2B1rTYnDCNt9GJsLG62HdbUgbb319qjOnbKOfNbZWbBoGvK3yr96VMhP4rW/pH1Ndqa4AQY7xFGcNkBv5ihsQLioOHSWPofrWhm2UN0bFuNz6Ch4jce5qZGGY+n3rM4mcY0nDQMwjVw08wBAVQc2SMkWLMRa55QAx12pdrZhSLPCY2J5nVJEZlXUKwJFjroKS4uNiEV1ZlcZlDC63vuBqKzmNx+jAhBErFUR4kk8+UldDa5s1hpu1N4fje3xEAYAdhmZDkC5sxCEWTlGUZfW49aGyJoqaeUI7nwbVsXkXKEXmbVje9vC4I0pLi2GihV9FW/6kXobFDUa/m/vVFjMfPI3ZwrbmcczFWKoQrMGX+XznLcXY7i1qEXN4TwQjFGhxWJdgLu23if8A2obByzCTs4DYykAm17AXNx0FhreuwKwRQ5UtbUre3tfU+GupqLiBeOBnhUtPI3ZxqrKrBbZpGBJGuXQHpcGvRu5cgdjvGhHJnusbQxL2cWZd7WzlbWuCy673sABprY8Nx3aYdYzG105QWGUW9O8NP9v62rLtDh4WEbvIGRQX7NGLIp3GYElF0ykoL2sCxBqz4ZxbD9sseEHa5hd27QGwJLXYuS5I10G17adObq6lScXtu7/LFvU0Kk/L6ljh5Z7G4Q5TZlVmvp4cuunprXOISGSFxEF7QAHLISLHfmygm9v/AHpuO4vHDKqtHKS2hdULBQBcXC3c3JsMqm5v4VQY3AmWZc05kw8i5RaQqQblhqou7AkcjEWAJ11Aw0dLukqk0kuU+n5/zAVJSTj2D8H4tNIkjyxJKrqVAS5Vitx1uXVlsQ6jXXTQmsvisI3bMrRZXeZbDOGKi7M+u7cq3JPh71a4bHzQYkYYoGCHZWJcKNVYu7AMSDqLDcgbAU7gTifiLylWWJELnMLWJNiCPEgW0uLE23ruRi6LlJRSja+H9iUJpxte7PQf4jL2a21bp4ADUnw8KrcVgY8SmIQdmZGGUcyhwQBa5CsV26g6dKhmxgEc+JmbItiFbNlIFjop3B1Go13qw4Fw3DQx/wASiglkzNNdmYqeYm7Emx8BauNTjte+7Tviyw3zlhnOUfhK74RwkmDQLjWiihjz3aVkaOR5HuGGoIbpYjUE6A61f8cnUQrGjITKrBGvaMDIzPI172QLrv1UX1JGE+KuMLM0cM5YYftMzSqtpY2GZQqgH8Mhdw12bMTtYVa/C2EkmVJnVFWICLDrJCcvZrZhIiZ1ysTa7a3yKRtc/Q1c0F7zm/XBPY5P3vTNFheKSFVGUzN+Z40aOIeYMrXff8hN/KrKLDpHcIttbkiwuTuSALXNv2psDvl52Vm8VUr+oLNrfz8anzBtNv8APL6j9q5salPd4QSTKf4mwSorSr2omRct4yfxf6Y3ADKVYnQlSVzG1qD4ziZcwWM4oZOUiIQupzDNdhIS5BDC5NgbeO1q2Cjv3Vv45UJB2uCQddaIGHuAuZtBYaRk/up1/Wtf4iNsk43i7lbisQspiQvJH2odbqWDXVkVhlGZQdxnuMoPKbm9cngw0EoCjtJwLpCrZ2APKMoZrQpa4zcqgX111s5cGjACQ5l00bKFFuugHhfy6WqnxaY2Mzdh2D5zeN3dgUAAGRlyntbWNjm67G1q9vhNW/3a40E7kHH+JTq8MTrFGZpFVDZpMpzC9zZVBOoyi5tc3FaPjrkCMiPtCGGmjEKdCwBIy7762vrobjKxY0pIFxMU000SCQWZnF9QGEcaIAb6XCtlB1I1qr+FpsFPMRKe2bEEzujZjHA9wDHdu/mzHmOnIo2y200qUFBxlx+4KkZSV4dF1xnExyoqGRSxdSED2z3zJaPUFwty2YaEr+me4tGqY7A4q8gzmRWLaqp7KRBGvUEkDl8bWG9ei4/ARyoY5FutgBbQgA3FrWIsdQQQRavNfjSB14Y2WQk4ecMdLsCGsSSG3BYsSb3O1hWWnsjWW3C4+48Zfl27ND8KY0SR5oGurA3bmHh4+Hp+lPxE6hsgBkI1PMc3XXW/L5m21VfxUcVDhVWCbKdS4RFD2I5RcmyAXubanxABpnDcYREio4lmlP8AM0ANtLm1wCFG1vK19+fX0zjlSur2t5epppPdJ3X1NNwXGF0JaEoAxAs+a9t21Vb66e1UvFPhoNMjRlWzK+aWUglCWz3sxGupA5bCw8qKwyygWDZUUaliAB5sdr/56wxvO6l0bMl7KwykPb8ynqL6X8vOs9KtKnOUopW+wdviujvC/wD5Q9i0pZJdpSFskmoDAFTYMOUnwtppcx8a4jMhTDrKWxLuVZe1lXKurswyrawuFUgXIa/oLicQzKVlUEEeH7jxHXb9b0Lg8ccVBHiYjafCt2UhcnniYMEZlBu2vLl3LL6V19JUnVi3PlE5Kz9f3JcIuOVy8s7oqqoXspWIazHRgwzNpuxsfOr3BQJGhRBZQbAXY9AdSSST1JJuetUXDYnaFp3meTtLZAbBQoOhCDRCfDUgAAkm9aCP83r9hVKkm8E35s5h/wCa3yjz6mlVPxnB4mSX8CTKMovZ2jPUa6Mrj2BHnelRjBW5GUV5lq50qvQ8xpUqozdEgxmBilxJMsav2eFDIHUMAWlVSbHQ6eINR4rHSIq5GyAZLBAEXa/dUAbjwpUqNT4USoJOTIngWRyzqCTr4C+S97DTdR/hNd+GMMgh7QDnad1LG5NlchRrsBbp60qVK+Ge1DexF7jzYEjcG4qn+H0AaT/bFEB42YNI2vW7MWJ6k0qVTj8LMaLxu6tcIAlw+g/kyNsL3MqAkHcXGnppSpUv6J+hKp16hnFsKrxMrA2YWNiQbXGlwQba1kcRwmK0Zs1wRY9pJp+U/m3IABPUUqVcX2fOSi1f9TOtS+A0nDHLhixJKAZfdghB/q08b+O9EfEUShZLDVRcHzAuKVKpzxBepm/uGI4vhlGKdwLFo1JsSLk2BJGx0AqPCfzp/wDxAvsEjNvPUmlSrrxbdL/yh5LP1NjNgInaDPGjWuOZQ2mXNbXpcA+wrQlRbbTa3S3h6UqVcWUn4VchUPMP9SB2JlWPlVXjcLuMzCQEkHQ6dDoK3XwvCqYPDBRb8GMnzJVSST11JpUq+i9rv/r4epztK/zmedfF/wAQYn+JliEzCNWICrZdr21FifegMRxbEROnZzyi6IT+IxHNe+hJ8KVKn08I+5WPI76StE9A4FxiZ1GZyfxguy93KGtt4mtSN/alSrNqlZRt5nHj8UiBHJF7/mI/e1Zr4vnZZ8Oisyq2csASLkKbHTW43B6HUUqVLpl/y0vUpP8ApsquE4ZXTI2Zlsd2Y3uTck3ux9dqzmEGbD47MSeznGW5J3aVSGv3xZQOa+1cpV2p/wBKX0MXs5v3yPUvhDEvJgIXdizFNSdzYka+wFUHHcMohxzgatIga+twHGljp1P60qVcX+59V+50/wDIxvxvxWf+OxAErgRscgViALEWBAtm971a/CMKriMQVABEaAf8spP60qVbfaCS00rfzJHSN7pG3wmFR4QGUMG7wOt9BvUuLgVcOVUZQqELlJBAAsLEajTrSpV8dGT3pX/UbJcGB+EGJgYEkgEWub2ukTG3ldibedEfB8zSYyaNzdWw84I2vkeHJqNbrmNj50qVfW0UlqanoZq3CL3GYZYxKiCy8j2ue818x18SoPrc7k3PQ975vtSpUKnxAZyH+afkH1NKlSooJ//Z";
    cout << check(imageData, 2, "12345") << endl;
    return 0;
}
