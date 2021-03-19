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

const string HOST = "asafe.ilivedata.com";
const string URI = "/api/v1/audio/check/submit";
const string endpoint_url = "https://asafe.ilivedata.com/api/v1/audio/check/submit";
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

string urlEncode(const string &value)
{
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i)
    {
        string::value_type c = (*i);
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
            continue;
        }

        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char)c);
        escaped << nouppercase;
    }

    return escaped.str();
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

string check(const string &audio_url, int type, const string &lang, const string &userId)
{
    std::stringstream jsonBody;
    jsonBody << "{";

    //-- sBase
    jsonBody << "\"audio\":\"" << audio_url << "\",";
    jsonBody << "\"lang\":\"" << lang << "\",";
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
    string audio_url = "https://speech-test.s3.cn-northwest-1.amazonaws.com.cn/speech/79b31026-d30a-11ea-aaa9-ac1f6b9346d0.wav";
    cout << check(audio_url, 1, "zh-CN", "12345") << endl;
    return 0;
}