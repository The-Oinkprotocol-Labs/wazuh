/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined (__linux__) || defined (__MACH__)
#include "wm_control.h"
#include "syscollector/syscollector.h"
#include "external/cJSON/cJSON.h"
#include "file_op.h"
#include "../os_net/os_net.h"
#include <ifaddrs.h>
#include "../config/config.h"

static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump(void);

static int verify_manager_conf(const char * path, char * output);
static int verify_agent_conf(const char * path, char * output);
// extern int Test_DBD(const char * path);

const wm_context WM_CONTROL_CONTEXT = {
    "control",
    (wm_routine)wm_control_main,
    (wm_routine)wm_control_destroy,
    (cJSON * (*)(const void *))wm_control_dump
};

char* getPrimaryIP(){
     /* Get Primary IP */
    char * agent_ip = NULL;
    char **ifaces_list;
    struct ifaddrs *ifaddr, *ifa;
    int size;
    int i = 0;
#ifdef __linux__
    int min_metric = INT_MAX;
#endif

    if (getifaddrs(&ifaddr) == -1) {
        mterror(WM_CONTROL_LOGTAG, "at getPrimaryIP(): getifaddrs() failed.");
        return agent_ip;
    }
    else {
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
            i++;
        }
        os_calloc(i, sizeof(char *), ifaces_list);

        /* Create interfaces list */
        size = getIfaceslist(ifaces_list, ifaddr);

        if(!ifaces_list[0]){
            mtdebug1(WM_CONTROL_LOGTAG, "No network interface found when reading agent IP.");
            os_free(ifaces_list);
            return agent_ip;
        }
    }
#ifdef __MACH__
    OSHash *gateways = OSHash_Create();
    if (getGatewayList(gateways) < 0){
        mtdebug1(WM_CONTROL_LOGTAG, "Unable to obtain the Default Gateway list");
        os_free(ifaces_list);
        return agent_ip;
    }
    gateway *gate;
#endif

    for (i=0; i<size; i++) {
        cJSON *object = cJSON_CreateObject();
#ifdef __linux__
        getNetworkIface_linux(object, ifaces_list[i], ifaddr);
#elif defined __MACH__
        if(gate = OSHash_Get(gateways, ifaces_list[i]), gate){
            if(!gate->isdefault){
                free(gate);
                continue;
            }
            if(gate->addr[0]=='l'){
                free(gate);
                continue;
            }
            getNetworkIface_bsd(object, ifaces_list[i], ifaddr, gate);
        }
#endif
        cJSON *interface = cJSON_GetObjectItem(object, "iface");
        cJSON *ipv4 = cJSON_GetObjectItem(interface, "IPv4");
        if(ipv4){
#ifdef __linux__
            cJSON * gateway = cJSON_GetObjectItem(ipv4, "gateway");
            if (gateway) {
                cJSON * metric = cJSON_GetObjectItem(ipv4, "metric");
                if (metric && metric->valueint < min_metric) {
                    cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
                    cJSON *address = cJSON_GetArrayItem(addresses,0);
                    if(agent_ip != NULL){
                        free(agent_ip);
                    }
                    os_strdup(address->valuestring, agent_ip);
                    min_metric = metric->valueint;
                }
            }
#elif defined __MACH__
            cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
            cJSON *address = cJSON_GetArrayItem(addresses,0);
            os_strdup(address->valuestring, agent_ip);
            cJSON_Delete(object);
            break;
#endif

        }
        cJSON_Delete(object);
    }
#if defined __MACH__
    OSHash_Free(gateways);
#endif

    freeifaddrs(ifaddr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }

    free(ifaces_list);

    return agent_ip;
}

void *wm_control_main(){
    int sock, peer;
    char *buffer = NULL, *output = NULL;
    ssize_t length;
    fd_set fdset;

    if (sock = OS_BindUnixDomain(DEFAULTDIR CONTROL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mterror(WM_CONTROL_LOGTAG, "Unable to bind to socket '%s': (%d) %s.", CONTROL_SOCK, errno, strerror(errno));
        return NULL;
    }

    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");
    while(1) {
        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
            case -1:
                if (errno != EINTR) {
                    // mterror_exit(WM_CONTROL_LOGTAG, "At send_ip(): select(): %s", strerror(errno));
                    mterror_exit(WM_CONTROL_LOGTAG, "At main(): select(): %s", strerror(errno));
                }
                continue;

            case 0:
                continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                // mterror(WM_CONTROL_LOGTAG, "At send_ip(): accept(): %s", strerror(errno));
                mterror(WM_CONTROL_LOGTAG, "At main(): accept(): %s", strerror(errno));
            }
            continue;
        }

        os_calloc(OS_MAXSTR+1, sizeof(char), buffer);

        switch (length = OS_RecvUnix(peer, OS_MAXSTR, buffer), length) {
            case -1:
                mterror(WM_CONTROL_LOGTAG, "At main(): OS_RecvUnix(): %s", strerror(errno));
                break;

            case 0:
                mtinfo(WM_CONTROL_LOGTAG, "Empty message from local client.");
                close(peer);
                break;

            case OS_MAXLEN:
                mterror(WM_CONTROL_LOGTAG, "Received message > %i", MAX_DYN_STR);
                close(peer);
                break;

            default:
                if(!strcmp(buffer, "get-notify-ip")) {
                    output = getPrimaryIP();
                    if(output){
                        OS_SendUnix(peer, output, 0);
                        free(output);
                    }
                    else{
                        OS_SendUnix(peer,"Err",4);
                    }
                }
                else if(strstr(buffer, "check-manager-configuration -f")) {
                    char filepath[PATH_MAX] = {0,};
                    char msg[OS_MAXSTR] = {0,};
                    if(looking_for_cfgfile(buffer, filepath, sizeof(filepath))) {
                        if(verify_manager_conf(filepath, msg) > 0) {
                            msg_to_json("ok", peer);
                        }
                        else {
                            msg_to_json(msg, peer);
                        }
                    }
                    else {
                        mterror(WM_CONTROL_LOGTAG, "\nThe file provided could not be found\n");
                    }
                }
                else if(strstr(buffer, "check-agent-configuration -f")) {
                    char filepath[PATH_MAX] = {0,};
                    char msg[OS_MAXSTR] = {0,};
                    if(looking_for_cfgfile(buffer, filepath, sizeof(filepath))) {
                        if(verify_agent_conf(filepath, msg) > 0) {
                            msg_to_json("ok", peer);
                        }
                        else {
                            msg_to_json(msg, peer);
                        }
                    }
                    else {
                        mterror(WM_CONTROL_LOGTAG, "\nThe file provided could not be found\n");
                    }
                }
                else {
                    // Request not found
                    buffer[strlen(buffer)-1] = '\0';
                    mterror(WM_CONTROL_LOGTAG, "Request: '%s' not supported.", buffer);
                }
                close(peer);
                break;
        }
        free(buffer);
        buffer = NULL;
    }


    return NULL;
}

void wm_control_destroy(){}

wmodule *wm_control_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_control_dump(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddItemToObject(root,"wazuh_control",wm_wd);
    return root;
}

int verify_manager_conf(const char * path, char * output) {

    if(Test_Authd(path) < 0) {
        return -1;
    }
    else if(Test_Remoted(path) < 0) {
        return -1;
    }
    // else if(Test_Execd(path) < 0) {
    //     return -1;
    // }
    else if(Test_ActiveResponse(path) < 0) {
        return -1;
    }
    else if(Test_Analysisd(path) < 0) {            // Test Global, Rules, Alerts, Cluster, CLabels
        return -1;
    }
    else if(Test_Localfile(path) < 0) {            // Test Localfile and Socket
        return -1;
    }
    else if(Test_Integratord(path) < 0) {
        return -1;
    }
    else if(Test_Syscheck(path) < 0) {
        return -1;
    }
    else if(Test_Rootcheck(path) < 0) {
        return -1;
    }
    else if(Test_Maild(path) < 0) {
        return -1;
    }
    else if(Test_WModule(path) < 0) {              // Test WModules, SCA and FluentForwarder
        return -1;
    }
    else if(Test_Agentlessd(path) < 0) {
        return -1;
    }
    else if(Test_DBD(path) < 0) {
        return -1;
    }

    return 0;
}

int verify_agent_conf(const char * path, char * output) {
    /*
     * Get ready for retrieving a output message
     * which will be sent to api_sock
     *
     * Similar to : wm_exec fuction in wm_exec.c
     * by reader function.
     *
     * Compose the output message as
     * CheckManagerConfiguration function (at execd.c) done
     *
     */

    if (Test_Syscheck(path) < 0) {
        return -1;
    } 
    else if (Test_Rootcheck(path) < 0) {
        return -1;
    } 
    else if (Test_Localfile(path) < 0) {          // Test Localfile and Socket
        return -1;
    }
    else if (Test_Client(path) < 0) {
        return -1;
    } 
    else if (Test_ClientBuffer(path) < 0) {
        return -1;
    }
    else if (Test_WModule(path) < 0) {            // Test WModules, SCA and FluentForwarder
        return -1;
    }
    else if (Test_Labels(path) < 0) {
        return -1;
    }
    else if (Test_ActiveResponse(path) < 0) {
        return -1;
    }

    return 0;
}

int looking_for_cfgfile(const char *buffer, char *filepath, size_t n) {
    char aux[PATH_MAX] = {0,};
    char file[PATH_MAX] = {0,};
    sscanf(buffer, "%*s%*s%s", aux);
    sprintf(file, "%s/%s", DEFAULTDIR, aux);
    minfo("\nFile to be checked :%s\n", file);

    if(access(file, F_OK) == 0) {
        strncpy(filepath, file, n-1);
        filepath[n-1] = '\0';
        return 1;
    }

    return 0;
}

void msg_to_json(char * output, int peer) {
    cJSON *result_obj = cJSON_CreateObject();

    char *json_output = NULL;
    char error_msg[OS_SIZE_4096 - 27] = {0};
    snprintf(error_msg, OS_SIZE_4096 - 27, "%s", output);

    if(strcmp(output, "ok") == 0) {
        cJSON_AddNumberToObject(result_obj, "error", 0);
        cJSON_AddStringToObject(result_obj, "message", "ok");
    }
    else {
        cJSON_AddNumberToObject(result_obj, "error", 1);
        cJSON_AddStringToObject(result_obj, "message", error_msg);
    }

    os_free(json_output);
    json_output = cJSON_PrintUnformatted(result_obj);

    cJSON_Delete(result_obj);
    mdebug1("Sending configuration check: %s", json_output);

    /* Start api socket */
    // int rc, api_sock;
    // if ((api_sock = StartMQ(EXECQUEUEPATHAPI, WRITE)) < 0) {
    //     merror(QUEUE_ERROR, EXECQUEUEPATHAPI, strerror(errno));
    //     os_free(json_output);
    //     continue;
    // }

    // if ((rc = OS_SendUnix(api_sock, json_output, 0)) < 0) {
    //     /* Error on the socket */
    //     if (rc == OS_SOCKTERR) {
    //         merror("socketerr (not available).");
    //         os_free(json_output);
    //         close(api_sock);
    //         continue;
    //     }

    //     /* Unable to send. Socket busy */
    //     mdebug2("Socket busy, discarding message.");
    // }
    // close(api_sock);

    minfo("JSON OUTPUT:\n\n%s\n\n", json_output);
    if(OS_SendUnix(peer, json_output, 0) < 0) {
        merror("Control socket not available!");
    }

    os_free(json_output);
}

#endif
