/*
 **
 ** Copyright 2021, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
#include <iostream>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <memory>
#include <climits>
#include <getopt.h>
#include <string.h>
#include <json/reader.h>
#include <json/writer.h>
#include <json/value.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <constants.h>
#include <utils.h>
#include "cppbor/cppbor.h"
#include "cppcose/cppcose.h"
#include <openssl/ecdsa.h>
#include <openssl/sha.h>

// static globals.
static std::string inputFileName;
static std::string outputFileName;
Json::Value root;
Json::Value writerRoot;

using namespace std;
using cppbor::Array;
using cppbor::Map;
using cppbor::Bstr;
using cppcose::CoseKey;
using cppcose::EC2;
using cppcose::ES256;
using cppcose::P256;
using cppcose::SIGN;
using cppcose::bytevec;


// static function declarations
static int processInputFile();
int processStoreFactoryAttestKeys();
int getRawAttestPrivateKey(bytevec& privKey);
int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret);
int processCertificateChain();
//--
static int readDataFromFile(const char *fileName, std::vector<uint8_t>& data);
static int addApduHeader(const int ins, std::vector<uint8_t>& inputData);
static int getStringValue(Json::Value& Obj, const char* key, std::string& str);

// Print usage.
void usage() {
    printf("Usage: Please give json files with values as input to generate the apdus command. Please refer to sample_json files available in the folder for reference. Sample json files are written using hardcode parameters to be used for testing setup on cuttlefilsh emulator and goldfish emulators\n");
    printf("construct_keymint_apdus [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-i, --input  jsonFile \t Input json file \n");
    printf("-o, --output jsonFile \t Output json file \n");
}

int ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret) {
        
    const uint8_t *data = pkcs8Blob.data();
    EVP_PKEY *evpkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &data, pkcs8Blob.size());
    if(!evpkey) {
        printf("\n Failed to decode private key from PKCS8, Error: %ld", ERR_peek_last_error());
        return FAILURE;
    }
    EVP_PKEY_Ptr pkey(evpkey);

    EC_KEY_Ptr ec_key(EVP_PKEY_get1_EC_KEY(pkey.get()));
    if(!ec_key.get()) {
        printf("\n Failed to create EC_KEY, Error: %ld", ERR_peek_last_error());
        return FAILURE;
    }

    //Get EC Group
    const EC_GROUP *group = EC_KEY_get0_group(ec_key.get());
    if(group == NULL) {
        printf("\n Failed to get the EC_GROUP from ec_key.");
        return FAILURE;
    }

    //Extract private key.
    const BIGNUM *privBn = EC_KEY_get0_private_key(ec_key.get());
    int privKeyLen = BN_num_bytes(privBn);
    std::unique_ptr<uint8_t[]> privKey(new uint8_t[privKeyLen]);
    BN_bn2bin(privBn, privKey.get());
    secret.insert(secret.begin(), privKey.get(), privKey.get()+privKeyLen);

    return SUCCESS;
}

int getIntValue(Json::Value& bootParamsObj, const char* key, uint32_t *value) {
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isInt())
        return FAILURE;

    *value = (uint32_t)val.asInt();

    return SUCCESS;
}

int getStringValue(Json::Value& Obj, const char* key, std::string& str) {
    Json::Value val = Obj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isString())
        return FAILURE;

    str = val.asString();

    return SUCCESS;

}

int getBlobValue(Json::Value& bootParamsObj, const char* key, std::vector<uint8_t>& blob) {
    Json::Value val = bootParamsObj[key];
    if(val.empty())
        return FAILURE;

    if(!val.isString())
        return FAILURE;

    std::string blobStr = hex2str(val.asString());

    for(char ch : blobStr) {
        blob.push_back((uint8_t)ch);
    }

    return SUCCESS;
}

// Parses the input json file. Prepares the apdu for each entry in the json
// file and dump all the apdus into the output json file.
int processInputFile() {

    // Parse Json file
    if (0 != readJsonFile(root, inputFileName)) {
        return FAILURE;
    }
    if (0 != processStoreFactoryAttestKeys()) {
        return FAILURE;
    }
    if (SUCCESS != writeJsonFile(writerRoot, outputFileName)) {
        return FAILURE;
    }
    printf("\n Successfully written json to outfile: %s\n ", outputFileName.c_str());
    return SUCCESS;
}

int getCertChain(std::vector<uint8_t>& certChain) {
        Json::Value certChainFiles = root.get(kAttestCertChain, Json::Value::nullRef);
        if (!certChainFiles.isNull()) {
            if (!certChainFiles.isArray()) {
                printf("\n Improper value for public_keys in json file \n");
                return FAILURE;
            }
            for (uint32_t i = 0; i < certChainFiles.size(); i++) {
                if(certChainFiles[i].isString()) {
                    /* Read the certificates. */
                    if(SUCCESS != readDataFromFile(certChainFiles[i].asString().data(), certChain)) {
                        printf("\n Failed to read the Root certificate\n");
                        return FAILURE;
                    }
                } else {
                    printf("\n Fail: Only proper certificate paths as a "
                            "string is allowed inside the json file. \n");
                    return FAILURE;
                }
            }
        } else {
            printf("\n Fail: cert chain value should be an array inside the json file. \n");
            return FAILURE;
        }
    return SUCCESS;
}

int getRawAttestPrivateKey(bytevec& privKey) {
    Json::Value keyFile = root.get(kAttestKey, Json::Value::nullRef);
    if (!keyFile.isNull()) {
        std::vector<uint8_t> data;

        std::string keyFileName = keyFile.asString();
        if(SUCCESS != readDataFromFile(keyFileName.data(), data)) {
            printf("\n Failed to read the attestation key from the file.\n");
            return FAILURE;
        }
        if (SUCCESS != ecRawKeyFromPKCS8(data, privKey)) {
            return FAILURE;
        }
    } else {
        printf("\n Improper value for device_unique_key in json file \n");
        return FAILURE;
    }
    return SUCCESS;
}

int processStoreFactoryAttestKeys() {
    std::vector<uint8_t> storeData;
    // 0x0001 | CERT_CHAIN_LEN | CERT_CHAIN | 0x0002 | RAW_ATTEST_PRIV_KEY_LEN | RAW_ATTEST_PRIV_KEY
    storeData.push_back(0x00);
    storeData.push_back(0x01);
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> certChain;
    if (SUCCESS != getCertChain(certChain)) {
        return FAILURE;
    }
    int certChainLen = certChain.size();
    if (certChainLen > USHRT_MAX) {
        return FAILURE;
    }
    // Cert chain len
    storeData.push_back(static_cast<uint8_t>((certChainLen >> 8) & 0xFF));
    storeData.push_back(static_cast<uint8_t>(certChainLen & 0xFF));
    // cert chain
    storeData.insert(storeData.end(), certChain.begin(), certChain.end());
    // 0x0002
    storeData.push_back(0x00);
    storeData.push_back(0x02);
    if (SUCCESS != getRawAttestPrivateKey(privateKey)) {
        return FAILURE;
    }
    int privateKeyLen = privateKey.size();
    if (privateKeyLen > USHRT_MAX) {
        return FAILURE;
    }
    // private key len
    storeData.push_back(static_cast<uint8_t>((privateKeyLen >> 8) & 0xFF));
    storeData.push_back(static_cast<uint8_t>(privateKeyLen & 0xFF));
    // raw private key
    storeData.insert(storeData.end(), privateKey.begin(), privateKey.end());

    printf("\n Constructed store factory attest keys successfully. \n");
    if (SUCCESS != addApduHeader(kInsProvisionData, storeData)) {
        return FAILURE;
    }
    // Write to json.
    writerRoot[kProvisionData] = getHexString(storeData);
    return SUCCESS;
}

int addApduHeader(const int ins, std::vector<uint8_t>& inputData) {
    if(USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le all set to 00.
        // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        //Extended length 3 bytes, starts with 0x00
        if (inputData.size() > 0) {
            inputData.insert(inputData.begin(), static_cast<uint8_t>(inputData.size() & 0xFF)); // LSB
            inputData.insert(inputData.begin(), static_cast<uint8_t>(inputData.size() >> 8)); // MSB
        }
        inputData.insert(inputData.begin(), static_cast<uint8_t>(0x00));
        //Expected length of output.
        //Accepting complete length of output every time.
        inputData.push_back(static_cast<uint8_t>(0x00));
        inputData.push_back(static_cast<uint8_t>(0x00));
    } else {
        printf("\n Failed to construct apdu. input data larger than USHORT_MAX.\n");
        return FAILURE;
    }

    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_P2));//P2
    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_P1));//P1
    inputData.insert(inputData.begin(), static_cast<uint8_t>(ins));//INS
    inputData.insert(inputData.begin(), static_cast<uint8_t>(APDU_CLS));//CLS
    return SUCCESS;
}

int readDataFromFile(const char *filename, std::vector<uint8_t>& data) {
    FILE *fp;
    int ret = SUCCESS;
    fp = fopen(filename, "rb");
    if(fp == NULL) {
        printf("\nFailed to open file: \n");
        return FAILURE;
    }
    fseek(fp, 0L, SEEK_END);
    long int filesize = ftell(fp);
    rewind(fp);
    std::unique_ptr<uint8_t[]> buf(new uint8_t[filesize]);
    if( 0 == fread(buf.get(), filesize, 1, fp)) {
        printf("\n No content in the file \n");
        ret = FAILURE;
        goto exit;
    }
    data.insert(data.end(), buf.get(), buf.get() + filesize);
exit:    
    fclose(fp);
    return ret;
}

int main(int argc, char* argv[]) {
    int c;
    struct option longOpts[] = {
        {"input",       required_argument, NULL, 'i'},
        {"output",       required_argument, NULL, 'o'},
        {"help",             no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
        return FAILURE;
    }

    /* getopt_long stores the option index here. */
    while ((c = getopt_long(argc, argv, ":hi:o:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'i':
                // input file
                inputFileName = std::string(optarg);
                std::cout << "input file: " << inputFileName << std::endl;
                break;
            case 'o':
                // output file
                outputFileName = std::string(optarg);
                std::cout << "output file: " << outputFileName << std::endl;
                break;
            case 'h':
                // help
                usage();
                return SUCCESS;
            case ':':
                printf("\n missing argument\n");
                usage();
                return FAILURE;
            case '?':
            default:
                printf("\n Invalid option\n");
                usage();
                return FAILURE;
        }
    }
    if (inputFileName.empty() || outputFileName.empty() || optind < argc) {
        printf("\n Missing mandatory arguments \n");
        usage();
        return FAILURE;
    }
    // Process input file; construct apuds and store in output json file.
    processInputFile();
    return SUCCESS;
}
