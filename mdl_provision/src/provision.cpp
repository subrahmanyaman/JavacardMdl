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
#include <vector>
#include <memory>
#include <getopt.h>
#include "socket.h"
#include <string.h>
#include <json/reader.h>
#include <json/value.h>
#include <constants.h>
#include <utils.h>
#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

#define SE_POWER_RESET_STATUS_FLAG (1 << 30)

Json::Value root;
static std::string inputFileName;
using cppbor::Item;
using cppbor::Array;
using cppbor::Uint;
using cppbor::MajorType;
bool printProvisionStatus = false;

// static function declarations
static uint16_t getApduStatus(std::vector<uint8_t>& inputData);
static int sendData(std::shared_ptr<SocketTransport>& pSocket, std::string input, std::vector<uint8_t>& response);
static int provisionData(std::shared_ptr<SocketTransport>& pSocket, std::string apdu, std::vector<uint8_t>& response);
static int provisionData(std::shared_ptr<SocketTransport>& pSocket, const char* jsonKey);
static int getUint64(const std::unique_ptr<Item> &item, const uint32_t pos, uint64_t *value);


// Print usage.
void usage() {
    printf("Usage: Please consturcture the apdu(s) with help of construct apdu tool and pass the output file to this utility.\n");
    printf("provision_keymint [options]\n");
    printf("Valid options are:\n");
    printf("-h, --help    show this help message and exit.\n");
    printf("-i, --input  jsonFile \t Input json file \n");

}

static uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
    // Last two bytes are the status SW0SW1
    uint8_t SW0 = inputData.at(inputData.size() - 2); 
    uint8_t SW1 = inputData.at(inputData.size() - 1); 
    return (SW0 << 8 | SW1);
}

static int sendData(std::shared_ptr<SocketTransport>& pSocket, std::string input, std::vector<uint8_t>& response) {

    std::vector<uint8_t> apdu(input.begin(), input.end());

    if(!pSocket->sendData(apdu, response)) {
        std::cout << "Failed to provision attestation key" << std::endl;
        return FAILURE;
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU
    // status.
    if ((getApduStatus(response) != APDU_RESP_STATUS_OK)) {
        printf("\n Received error response with error: %d\n", getApduStatus(response));
        return FAILURE;
    }
    // remove the status bytes
    response.pop_back();
    response.pop_back();
    return SUCCESS;
}

int provisionData(std::shared_ptr<SocketTransport>& pSocket, std::string apdu, std::vector<uint8_t>& response) {
    if (SUCCESS != sendData(pSocket, apdu, response)) {
        return FAILURE;
    }
    // auto [item, pos, message] = cppbor::parse(response);
    // if(item != nullptr) {
    //     uint64_t err;
    //     if(MajorType::ARRAY == item.get()->type()) {
    //         if(SUCCESS != getUint64(item, 0, &err)) {
    //             printf("\n Failed to parse the error code \n");
    //             return FAILURE;
    //         }
    //     } else if (MajorType::UINT == item.get()->type()) {
    //         const Uint* uintVal = item.get()->asUint();
    //         err = uintVal->value();
    //     }
    //     err = unmaskPowerResetFlag(err);
    //     if (err != 0) {
    //         printf("\n Failed with error:%ld", err);
    //         return FAILURE;
    //     }
    // } else {
    //     printf("\n Failed to parse the response\n");
    //     return FAILURE;
    // }
    return SUCCESS;
}

int provisionData(std::shared_ptr<SocketTransport>& pSocket, const char* jsonKey) {
    Json::Value val = root.get(jsonKey, Json::Value::nullRef);
    if (!val.isNull()) {
        if (val.isString()) {
            std::vector<uint8_t> response;
            if (SUCCESS != provisionData(pSocket, hex2str(val.asString()), response)) {
                printf("\n Error while provisioning %s \n", jsonKey);
                return FAILURE;
            }
        } else {
            printf("\n Fail: Expected (%s) tag value is string. \n", jsonKey);
            return FAILURE;
        }
    }
    printf("\n Successfully provisioned %s \n", jsonKey);
    return SUCCESS;
}

int openConnection(std::shared_ptr<SocketTransport>& pSocket) {
    if (!pSocket->isConnected()) {
        if (!pSocket->openConnection()) {
            printf("\nFailed to open connection.\n");
            return FAILURE;
        }
    }
    return SUCCESS;
}

// Parses the input json file. Sends the apdus to JCServer.
int processInputFile() {
    // Parse Json file
    if (0 != readJsonFile(root, inputFileName)) {
        return FAILURE;
    }
    std::shared_ptr<SocketTransport> pSocket = SocketTransport::getInstance();
    if (SUCCESS != openConnection(pSocket)) {
        printf("\n Failed to open connection \n");
        return FAILURE;
    }
 
    if (0 != provisionData(pSocket, kProvisionData)) {
        return FAILURE;
    }    
    return SUCCESS;
}

int main(int argc, char* argv[]) {
    int c;
    bool provisionStatusSet = false;
    bool lockProvisionSet = false;
    bool unlockProvisionSet = false;
    bool seFactoryLockSet = false;

    struct option longOpts[] = {
        {"input",       required_argument, NULL, 'i'},
        {"help",        no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    if (argc <= 1) {
        printf("\n Invalid command \n");
        usage();
        return FAILURE;
    }

    /* getopt_long stores the option index here. */
    while ((c = getopt_long(argc, argv, ":hlufsvi:", longOpts, NULL)) != -1) {
        switch(c) {
            case 'i':
                // input file
                inputFileName = std::string(optarg);
                std::cout << "input file: " << inputFileName << std::endl;
                break;
            case 'h':
                // help
                usage();
                return SUCCESS;
            case ':':
                printf("\n Required arguments missing.\n");
                usage();
                return FAILURE;
            case '?':
            default:
                printf("\n Invalid option\n");
                usage();
                return FAILURE;
        }
    }

    if (argc < 3) {
        usage();
        return FAILURE;
    }
    // Process input file; send apuds to JCServer over socket.
    if (SUCCESS != processInputFile()) {
        return FAILURE;
    }

    return SUCCESS;
}


