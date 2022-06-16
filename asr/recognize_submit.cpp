#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <iomanip>
#include <memory.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <curl/curl.h>

using namespace std;

const string HOST = "asr.ilivedata.com";
const string URI = "/api/v1/speech/recognize/submit";
const string PROJECT_ID = "YOUR_PROJECT_ID_GOES_HERE";
const string SECRET_KEY = "YOUR_SECRET_KEY_GOES_HERE";

string getISO8601UTCTime()
{
    time_t now;
    time(&now);
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    gmtime_r(&now, &tm);
    char buf[sizeof "2011-10-08T07:07:09Z"];
    strftime(buf, sizeof buf, "%FT%TZ", &tm);
    return string(buf);
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
        else if (str[i] == ' ')
            strTemp += "+";
        else
        {
            strTemp += '%';
            strTemp += toHex((unsigned char)str[i] >> 4);
            strTemp += toHex((unsigned char)str[i] % 16);
        }
    }
    return strTemp;
}

string sha256(const string &str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
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

bool sendHttpRequest(const string &sign, const string &body, const string &nowTime, string &response)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        cout << "curl init fail" << endl;
        return false;
    }

    struct curl_slist *headerList = NULL;
    headerList = curl_slist_append(headerList, string("X-AppId: " + PROJECT_ID).c_str());
    headerList = curl_slist_append(headerList, string("X-TimeStamp: " + nowTime).c_str());
    headerList = curl_slist_append(headerList, string("Content-type: application/json").c_str());
    headerList = curl_slist_append(headerList, string("Authorization: " + sign).c_str());
    headerList = curl_slist_append(headerList, string("Host: " + HOST).c_str());
    headerList = curl_slist_append(headerList, string("Connection: keep-alive").c_str());

    string url = "https://" + HOST + URI;
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
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

string recognize(const string &audioUrl, const string &languageCcode, const string &userId, bool speakerDiarization)
{

    const string codeC = "PCM";
    const int sampleRateHertz = 16000;

    stringstream queryBodyJsonStream;
    queryBodyJsonStream << "{\"languageCode\": \"" << languageCcode << "\", \"diarizationConfig\": {\"enableSpeakerDiarization\": " << speakerDiarization << "}, \"config\": {\"codec\": \"" << codeC << "\", \"sampleRateHertz\": " << sampleRateHertz << "}, \"audio\": \"" << audio << "\", \"userId\": \"" << userId << "\"}";

    string queryBodyJson = queryBodyJsonStream.str();

    string nowTime = getISO8601UTCTime();

    stringstream parameter;
    parameter << "POST\n"
              << HOST << "\n"
              << URI << "\n"
              << sha256(queryBodyJson) << "\n"
              << "X-AppId:" << PROJECT_ID << "\n"
              << "X-TimeStamp:" << nowTime;

    string sign = createSign(parameter.str(), SECRET_KEY);
    sign = base64Encode(sign);

    string response;
    if (!sendHttpRequest(sign, queryBodyJson, nowTime, response))
        cout << "recognize fail" << endl;

    return response;
}

// g++ -o recognize recognize.cpp -lcrypto -lcurl
int main(int argc, char *argv[])
{
    string audioUrl = "https://rcs-us-west-2.s3.us-west-2.amazonaws.com/test.wav";

    cout << recognize(audioUrl, "zh-CN", "12345678", true) << endl;

    return 0;
}
