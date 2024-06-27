# /*****************************************************************************
# * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
# *                                                                           *
# * This Software is the property of Palo Alto Networks. The Software and all *
# * accompanying documentation are copyrighted.                               *
# *****************************************************************************/
#
# Copyright 2016 Palo Alto Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import boto3
import logging
import json
import http.client
import xml.etree.ElementTree as et
import time
from urllib.parse import urlparse
from contextlib import closing
import ssl
import urllib.request, urllib.error, urllib.parse

ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
lambda_client = boto3.client('lambda')
as_client = boto3.client('autoscaling')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


PortalMgmtIp = ""
PortalDPIp = ""
api_key = ""
gcontext = ""
job_id = ""
asg_name = ""

def init_portal_lambda_handler(event, context):
    global PortalMgmtIp
    global PortalDPIp
    global api_key
    global gcontext
    global job_id
    global asg_name

    logger.info('[INFO]: got event{}'.format(event))
#    set_asg = False

#Lambda launched via custom resource in CFT
    if ('RequestType'in event):
        if event['RequestType'] == 'Delete':
            logger.info('[INFO]: Sending delete response to S3 URL for stack deletion to proceed')
            if delete_stack() == True:
                send_response(event, context, "SUCCESS")
            else:
                send_response(event, context, "FAILURE")
                return
            return
        elif event['RequestType'] == 'Create':
            logger.info('[INFO]: Sending create response to S3 URL for stack creation to proceed')
#            set_asg = True
            if(send_response(event, context, "SUCCESS")) == 'false':
                logger.info('[ERROR]: Got ERROR in sending response to S3 URL for custom resource...quitting')
                return

        PortalMgmtIp = event['ResourceProperties'].get('GPPortalMgmtIp')

    #Get current function name so we can call it later:
    #This is because lambda functions created in CFTs have misc identifiers
    #and by specifying a function name, you cannot launch multiple cft's at the same time
        this_func_name = event.get('ServiceToken').split(":")[6]

        logger.info ("[INFO]: Function Name = {}".format(this_func_name))

        if PortalMgmtIp == None:
            logger.info('[ERROR]: Did not get Portal MGMT IP address')
            return

        PortalDPIp = event['ResourceProperties'].get('GPPortalDPIp')
        if PortalDPIp == None:
            logger.info('[ERROR]: Did not get Portal DP IP address')
            return

        asg_name = event['ResourceProperties'].get('ASGName')
        if asg_name == None:
            logger.info('[ERROR]: Did not get autoscaling group name')
            return


#Self called lambda function
    elif('portal-mgmt-ip' in event):
        PortalMgmtIp = event.get('portal-mgmt-ip')
        if PortalMgmtIp == None:
            logger.info("[ERROR]: didn't get Portal MGMT IP addresses")
            raise Exception("[ERROR]: Didn't get Portal MGMT IP")
        PortalDPIp = event.get('portal-dp-ip')
        if PortalMgmtIp == None:
            logger.info("[ERROR]: didn't get Portal DP IP addresses")
            raise Exception("[ERROR]: Didn't get Portal DP IP")
        this_func_name = event.get('init-portal-func-name')
        if this_func_name == None:
            logger.info("[ERROR]: Didn't get function name")
            raise Exception("[ERROR]: Didn't get function name")
        else:
            logger.info("[INFO]: function name {}".format(this_func_name))

    else:
        logger.info("[ERROR]: How did I get here?")
        raise Exception("[ERROR]: How did I get here?")


    #The api key is pre-generated for  api_user/Pal0Alt0
    api_key = "LUFRPT11dEtJM0tPTzVHMnJhelpHUzVDN2k5clpTd0E9TUdXZUpoeG5LOVJXemxuVGZ6VGtKdWNlckU2d2RoK2U2RGRxVU1Oc3VJaz0="
    #Need this to by pass invalid certificate issue. Should try to fix this
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    #Set Autoscaling group minimum to 1
#    if set_asg == True:
#        try:
#            as_client.update_auto_scaling_group(
#                        AutoScalingGroupName=asg_name,
#                        MinSize=1
#            )
#        except Exception as e:
#            logger.info("[ERROR]: Error setting  min size for autoscaling group")
#            logger.info("[RESPONSE]: {}".format(e))
#            raise Exception("[ERROR]: Error setting min size for autoscaling group")
#            return
#        else:
#            logger.info("[INFO]: Set autoscaling min size to 1...should trigger add_eni lambda")
#            set_asg = False


    #Continue initializing portal
    err = 'no'
    while (err != 'yes'):
        #err = check_fw_up()
        err = check_auto_commit_status()
        if err == 'cmd_error':
            logger.info("[ERROR]: Command error from fw")
            return
        elif err == 'no':
            logger.info("[INFO] FW is not up...yet")
            if (context.get_remaining_time_in_millis())/1000/60 < 2:
                logger.info("[INFO] have less than two minutes so call self")
                parameters ={
                    "portal-mgmt-ip": PortalMgmtIp,
                    "portal-dp-ip": PortalDPIp,
                    "init-portal-func-name": this_func_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    return
            else:
                #since we 2 or more minutes left of execution time, sleep (30) and trya again?
                logger.info("[INFO]: 2 or more minutes left in lambda function. So will check again in 30s")
                time.sleep(30)
                continue
        elif err == 'almost':
            #this means autocommit is happening
            logger.info("[INFO]: FW is up, but chassis is not ready")
            if (context.get_remaining_time_in_millis())/1000/60 < 2:    #get remaining time in minutes
                logger.info("[INFO]: Have less than two minutes but fw is almost up, so call self and exit")
                parameters ={
                    "portal-mgmt-ip": PortalMgmtIp,
                    "portal-dp-ip": PortalDPIp,
                    "init-portal-func-name": this_func_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    return
            else:
                #since we 2 or more minutes left of execution time, sleep (30) and trya again?
                logger.info("[INFO]: 2 or more minutes left in lambda function. since autocommit is happening, sleep 10")
                time.sleep(10)
                continue
        elif err == 'yes':
            logger.info("[INFO]: FW is up, but is there enough time left?")
            if (context.get_remaining_time_in_millis())/1000/60 < 3:
                logger.info("[INFO]: No. 3 or less minutes remaining. So call self and exit")
                parameters ={
                    "portal-mgmt-ip": PortalMgmtIp,
                    "portal-dp-ip": PortalDPIp,
                    "init-portal-func-name": this_func_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    return
            else:
                logger.info("[INFO]: FW is up and there is 3 or more minutes left. So exit the loop and config portal...finally!!")
                time.sleep(10)
                break


    #Config portal
    #once it is up, need to figure out how to update the portal with this EIP?????
    if (send_command('certificate') == 'false'):
        logger.info("[ERROR]: Generate certificate error")
        return
    else:
        logger.info("[INFO]: Generate certificate success")

    if(send_command('tls_profile') == 'false'):
        logger.info("[ERROR]: Could not update ssl/tls profile for portal with generated cert")
        return
    else:
        logger.info("[INFO]: Updated ssl/tls profile with generated cert")

    if(send_command('commit_portal') == 'false'):
        logger.info("[ERROR]: Commit portal job error")
        return
    else:
        logger.info("[INFO]: Commit portal successful")
        return


    logger.info("[ERROR]: Should not be here")
    return


def send_command(cmd):
    global PortalMgmtIp
    global PortalDPIp
    global job_id
    global gconext
    global api_key
    gconext = ""

    job_id = ""

    if (cmd == 'certificate'):
        cmd_string = "https://"+PortalMgmtIp+"/api/?type=op&cmd=<request><certificate><generate><signed-by>rootCA</signed-by><certificate-name>portal-cert</certificate-name><name>"+PortalDPIp+"</name><algorithm><RSA><rsa-nbits>2048</rsa-nbits></RSA></algorithm></generate></certificate></request>&key="+api_key
    elif (cmd == 'tls_profile'):
        cmd_string = "https://"+PortalMgmtIp+"/api/?type=config&action=set&xpath=/config/shared/ssl-tls-service-profile/entry[@name='portal-ssl-tls']&element=<certificate>portal-cert</certificate>&key="+api_key
    elif (cmd == 'commit_portal'):
        cmd_string = "https://"+PortalMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
    else:
        logger.info("[ERROR]: Unknown command")
        return 'false'

    logger.info('[INFO]: Sending command: %s', cmd_string)
    try:
        response = urllib.request.urlopen(cmd_string, context=gcontext, timeout=5).read()
        #Now we do stuff to the portal
        logger.info("[RESPONSE] in send command: {}".format(response))
    except:
         logger.info("[ERROR]: Something bad happened when sending command")
         return  'false'
    else:
        logger.info("[INFO]: Got a (good?) response from command")

    resp_header = et.fromstring(response)
    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall")
        return 'false'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        return 'false'

    if resp_header.attrib['status'] == 'success':
    #The fw responded with a successful command execution. No need to check what the actual response is
        logger.info("[INFO]: Successfully executed command")
        return 'true'

    if(cmd == 'commit_portal'):
        for element in resp_header:
            for iterator in element:
                if iterator.tag == 'job':
                    job_id = iterator.text
                    if job_id == None:
                        logger.info("[ERROR]: Didn't get a job id")
                        return 'false'
                    else:
                        break #break out of inner loop
                else:
                    continue
            break #break out of outer loop
        if cmd == 'commit_portal':
            cmd_string = "https://"+PortalMgmtIp+"/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
        else:
            logger.info("[ERROR]: send command not commit portal so error!")
            return 'false'
        if (send_command(cmd_string) == 'false'):
            logger.info("[ERROR]: Commit status check failed")
            return 'false'






#the context object gives remaining time in milliseconds so that can be used to determine how long to sleep
#so something like ,check time remaining, if greater than 2 minute then sleep for 1 minute and check again
#if 2 less than 2 minutes , check fw and if not up, call lambda function and exit
#think of a more generic way?? what if there is 1 minute left and fw is up?
#call lambda again and exit?
def check_fw_up():
    global gcontext
    global PortalMgmtIp
    global api_key
    cmd = "https://"+PortalMgmtIp+"/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key="+api_key
    #Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib.request.urlopen(cmd, context=gcontext, timeout=5).read()
        #Now we do stuff to the portal
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW. So maybe not up!")
        return 'no'
        #sleep and check again?
    else:
        logger.info("[INFO]: FW is up!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'success':
    #The fw responded with a successful command execution. So is it ready?
        for element in resp_header:
            if element.text.rstrip() == 'yes':
            #Call config portal command?
                logger.info("[INFO]: FW is ready for configure")
                return 'yes'
            else:
                return 'almost'
            #The fw is still not ready to accept commands
            #so invoke lambda again and do this all over? Or just retry command?

####WORKAROUND UNTIL I FIND A BETTER WAY TO CHECK FW MGMT-SERVICES IS UP
def check_auto_commit_status():
    global job_id
    global gcontext
    global PortalMgmtIp
    global PortalDPIp
    global api_key

    job_id = '1' #auto commit job id is always 1
    cmd = "https://"+PortalMgmtIp+"/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
    #Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib.request.urlopen(cmd, context=gcontext, timeout=5).read()
        #Now we do stuff to the portal
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW. So maybe not up!")
        return 'no'
        #sleep and check again?
    else:
        logger.info("[INFO]: FW is up!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        for element1 in resp_header:
            for element2 in element1:
                if element2.text == "job 1 not found":
                    logger.info("[INFO]: Job 1 not found...so try again")
                    return 'almost'
                elif "Invalid credentials" in element2.text:
                    logger.info("[INFO]:Invalid credentials...so try again")
                    return 'almost'
                else:
                    logger.info("[ERROR]: Some other error when checking auto commit status")
                    return 'cmd_error'


    if resp_header.attrib['status'] == 'success':
    #The fw responded with a successful command execution. So is it ready?
        for element1 in resp_header:
            for element2 in element1:
                for element3 in element2:
                    if element3.tag == 'status':
                        if element3.text == 'FIN':
                            logger.info("[INFO]: FW is ready for configure")
                            return 'yes'
                        else:
                            return 'almost'





def send_response(event, context, responseStatus):
    response = {
                'Status': responseStatus,
                'Reason': 'See the details in CloudWatch Log Stream.',
                'StackId': event['StackId'],
                'RequestId': event['RequestId'],
                'LogicalResourceId': event['LogicalResourceId'],
                'PhysicalResourceId': event['LogicalResourceId']
               }
    logger.info('RESPONSE: ' + json.dumps(response))
    parsed_url = urlparse(event['ResponseURL'])
    if (parsed_url.hostname == ''):
        logger.info('[ERROR]: Parsed URL is invalid...')
        return 'false'

    logger.info('[INFO]: Sending Response...')
    try:
        with closing(http.client.HTTPSConnection(parsed_url.hostname)) as connection:
            connection.request("PUT", parsed_url.path+"?"+parsed_url.query, json.dumps(response))
            response = connection.getresponse()
            if response.status != 200:
                logger.info('[ERROR]: Received non 200 response when sending response to cloudformation')
                logger.info('[RESPONSE]: ' + response.msg)
                return 'false'
            else:
                logger.info('[INFO]: Got good response')

    except:
        logger.info('[ERROR]: Got ERROR in sending response...')
        return 'false'
    finally:
        connection.close()
        return 'true'

def delete_stack():


    try:
        rules_list = events_client.list_rules().get('Rules')
    except Exception as e:
        logger.info("[ERROR]: Error listing rules")
        logger.info("[RESPONSE]: {}".format(e))
        return False
    if not rules_list:
        logger.info(['INFO: No rules...so no target and lambda functions'])
    else:
        for rule in rules_list:
            rule_name = rule.get('Name')
            logger.info(["Rule Name]: {}".format(rule_name)])
            target_id_list = events_client.list_targets_by_rule(Rule=rule_name).get('Targets')
            for tid in target_id_list:
                try:
                    events_client.remove_targets(
                        Rule=rule_name,
                        Ids=[
                            tid.get('Id')
                        ]
                    )
                except Exception as e:
                    logger.info("[ERROR]: Error removing target. ID: {}".format(tid.get('Id')))
                    logger.info("[RESPONSE]: {}".format(e))
                    return False
                else:
                    logger.info("[INFO]: Successfully removed target lambda function for rule")

                try:
                    events_client.delete_rule(
                        Name=rule_name
                    )
                except Exception as e:
                    logger.info("[ERROR]: Error removing rule")
                    logger.info("[RESPONSE]: {}".format(e))
                    return False
                else:
                    logger.info("[INFO]: Successfully deleted rule")
                lambda_func_name = rule_name.replace("Rule", "")
                try:
                    lambda_client.delete_function(
                        FunctionName=lambda_func_name
                    )
                except Exception as e:
                    logger.info("[ERROR]: Error deleting lambda function {}".format(lambda_func_name))
                    logger.info("[RESPONSE]: {}".format(e))
                    return False
                else:
                    logger.info("[INFO]: Successfully deleted lambda function")

    if (release_addresses('GPGateway DP') == False):
        return False

    if (release_addresses('GPGateway Mgmt') == False):
        return False

    return True




def release_addresses(filter_value):
    logger.info("INFO]: Releasing addresses for "+filter_value)
    try:
        interfaces_list = ec2_client.describe_network_interfaces(
                                    Filters=[
                                        {
                                         'Name': 'description',
                                         'Values' : [filter_value]
                                        },
                                        {
                                         'Name': 'status',
                                         'Values': ['in-use']
                                        }])
    except:
        logger.info("[ERROR]: Error getting network interfaces")
        return False

    if not interfaces_list.get('NetworkInterfaces'):
        logger.info("[INFO]: No network interfaces to delete")
    else:
        for eni in interfaces_list.get('NetworkInterfaces'):
            if eni.get('Association').get('PublicIp') != None:
                try:
                    logger.info("[INFO]: Disassociating IP address.")
                    ec2_client.disassociate_address(PublicIp=eni.get('Association').get('PublicIp'))
                except Exception as e:
                        logger.info("[ERROR]: Error whilst disassociating elastic IP addresses")
                        logger.info("[RESPONSE]: {}".format(e))
                        return False

            if eni.get('Association').get('AllocationId') != None:
                try:
                    logger.info("[INFO]: Releasing IP address.")
                    ec2_client.release_address(AllocationId=eni.get('Association').get('AllocationId'))
                except Exception as e:
                    logger.info("[ERROR]: Error whilst releasing elastic IP addresses")
                    logger.info("[RESPONSE]: {}".format(e))
                    return False

            if filter_value == 'GPGateway DP':
                if detach_and_delete_interfaces(eni) == True:
                    logger.info("[INFO] Detached and deleted interfaces")
                    return True
                else:
                    return False

def detach_and_delete_interfaces(eni):

    if eni.get('Attachment').get('AttachmentId') != None:
        try:
            logger.info("[INFO]: Detaching network interface.")
            ec2_client.detach_network_interface(AttachmentId=eni.get('Attachment').get('AttachmentId'), Force=True)
        except Exception as e:
            logger.info("[ERROR]: Error detaching network interface id {}".format(eni))
            logger.info("[Exception]: {}".format(e))
            return False
        else:
            logger.info("[INFO]: Detached network interface.")
    #return True

    #WAIT HERE for interface available
    try:
        waiter = ec2_client.get_waiter('network_interface_available')
        waiter.wait(NetworkInterfaceIds=[eni.get('NetworkInterfaceId')], Filters= [{'Name' : 'status', 'Values': ['available']}])
    except Exception as e:
        logger.info("[ERROR]: ENI failed to reach desired state {}".format(e))
        return False

    try:
        logger.info("[INFO]: Deleting network interface")
        ec2_client.delete_network_interface(NetworkInterfaceId=eni.get('NetworkInterfaceId'))
    except Exception as e:
        logger.info("[ERROR]: Error deleting network interface id {}".format(eni.get('NetworkInterfaceId')))
        logger.info("[Exception]: {}".format(e))
        return False
    else:
        logger.info("[INFO]: Deleted network interface. Id: {}".format(eni.get('NetworkInterfaceId')))

    return True

