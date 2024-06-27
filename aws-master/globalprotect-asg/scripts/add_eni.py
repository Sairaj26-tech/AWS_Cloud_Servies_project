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
import json
import logging
import botocore


asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')

lambda_client = boto3.client('lambda')

logger = logging.getLogger()
logger.setLevel(logging.INFO)
instanceId = ""
metadata = ""
gwDpIp = ""
gwMgmtIp = ""
subnetId = ""
securityGroups = ""
PortalMgmtIp = ""
config_gw_func = ""
lambda_bucket_name = ""

def add_eni_lambda_handler(event, context):

    global metadata
    global instanceId
    global gwDpIp
    global gwMgmtIp
    global subnetId
    global securityGroups
    global PortalMgmtIp
    global config_gw_func
    global lambda_bucket_name

    event_type = ""


    #Coming here via Sns?
    if ('Records' in event):
        message = json.loads(event['Records'][0]['Sns']['Message'])
        logger.info("[MESSAGE]: {}".format(message))
        if 'Event' in message:
            if (message.get('Event') == "autoscaling:TEST_NOTIFICATION"):
                logger.info("[INFO]: GOT TEST NOTIFICATION. Do nothing")
                return
            elif(message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH"):
                logger.info("[INFO]: GOT launch notification...will get launching event from lifecyclehook")
                #logger.info("[EVENT]: {}".format(event))
                return
            elif(message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE"):
                logger.info("[INFO]: GOT terminate notification....will get terminating event from lifecyclehook")
                return
            elif (message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE_ERROR"):
                logger.info("[INFO]: GOT a GW terminate error...raise exception for now")
                raise Exception ("Failed to terminate a GW in an autoscale event")
            elif (message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH_ERROR"):
                logger.info("[INFO]: GOT a GW launch error...raise exception for now")
                raise Exception ("Failed to launch a GW in an autoscale event")
        elif 'LifecycleTransition' in message:
            if (message.get('LifecycleTransition') == "autoscaling:EC2_INSTANCE_LAUNCHING"):
                logger.info("[INFO] Lifecyclehook Launching\n")
                event_type = 'launch'
            elif (message.get('LifecycleTransition') == "autoscaling:EC2_INSTANCE_TERMINATING"):
                logger.info("[INFO] Lifecyclehook Terminating\n")
                event_type = 'terminate'
            else:
                logger.info("[ERROR]/[INFO] One of the other lifeycycle transition messages received\n")
                event_type = 'other'
    else:
        logger.info("[ERROR]: Something else entirely")
        raise Exception("[ERROR]: Something else entirely")

    if event_type == 'launch' or event_type == 'terminate':
        instanceId = message.get('EC2InstanceId')
        if instanceId == None:
            logger.info("[ERROR] Instance ID is None. Should not be!")
            terminate('false', message)
            raise Exception('Failed to get EC2 Instance Id in add_eni.py')
        metadata = message.get('NotificationMetadata')
        if metadata == None:
            logger.info("[ERROR] Metadata is None. Should not be!")
            terminate('false', message)
            raise Exception('Failed to get Notification Metadata in add_eni.py')
        #The Notification Metadata object for lifecyclehook is used to pass parameters:
        #the structure for now is hardcoded and it is a comma separated list
        #{
        #"subnet where the eni should reside",
        #"security group for eni",
        #"mgmt ip of portal",
        #" Config gw function name"
        #}
        subnetId = metadata.split(",")[0]
        securityGroups = metadata.split(",")[1]
        PortalMgmtIp = metadata.split(",")[2]
        config_gw_func = metadata.split(",")[3]
        lambda_bucket_name = metadata.split(",")[4]
    if event_type == 'launch': #or event_type == 'cft-launch':
        launch_gw(event, message)
        return
    elif event_type == 'terminate': #or event_type == 'cft-terminate':
        terminate_gw(event, message)
        return
    else:
        terminate('false', message)
        return

####LAUNCH CODE STARTS HERE

def launch_gw(event, message):

    global metadata
    global instanceId
    global gwDpIp
    global gwMgmtIp
    global subnetId
    global securityGroups
    global PortalMgmtIp
    global config_gw_func
    global lambda_bucket_name


    logger.info("[INFO]: Launching GW as part of autoscale event")
    #Get interfaces for this instance with device index 0
    while True:
        try:
            interfaces_dict = ec2_client.describe_network_interfaces(
                Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [instanceId]
                },
                {
                    'Name': 'attachment.device-index',
                    'Values': ['0']
                }]
        )
        except:
            logger.info('[WARN] Is interface 0 not ready?...Retrying')
            continue
        logger.info('[INFO] Interface 0 ready and set to go')
        break

    #Associate EIP to the first interface
    eniId = (interfaces_dict.get('NetworkInterfaces')[0]).get('NetworkInterfaceId')
    ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eniId,Description={'Value': 'GPGateway Mgmt'})
    if eniId == None:
         logger.info("[ERROR] Netowrk Interface ID is None. Should not be!")
         #raise Exception('Network interface ID is none : ' inspect.stack()[1][3]);
         terminate('false', message)
         return
   # eniId = interfaces_dict['NetworkInterfaces'][0]['NetworkInterfaceId']

    err = allocate_and_attach_eip(eniId)
    if err == 'false':
        logger.info('[ERROR] allocate and attach failed')
        #raise Exception('[ERROR] allocate and attach failed : ' inspect.stack()[1][3]);
        terminate('false', message)
        return
    else:
        logger.info('[INFO] allocate and attach successful')
        gwMgmtIp = err.get('PublicIp')
        if gwMgmtIp == None:
            logger.info("[ERROR]: gwMgmtIp is None")
            terminate('false', message)
            return
        else:
            logger.info("[INFO]: gwMgmtIp is %s", gwMgmtIp)

    #CreateEni
    err = createEni(subnetId, securityGroups)
    if err == 'false':
        logger.info("Error: Eni creation failed\n")
        terminate('false', message)
        return
    else:
        eniId = err

    #Wait for the ENI to be 'available'
    err = waitEniReady(eniId)
    if err == 'false':
        logger.info("ERROR: Failure waiting for ENI to be ready")
        terminate('false', message)
        return

    #Attach the network interface to the instance
    err = attachEni(instanceId, eniId)
    if err == 'false':
        logger.info("[ERROR]: Failure attaching ENI to instance")
        terminate('false', message)
        return
    else:
        logger.info("[INFO]: Success! Attached ENI to instance")

    err = allocate_and_attach_eip(eniId)
    if err == 'false':
        logger.info('[ERROR] allocate and attach failed')
        terminate('false', message)
        return
    else:
        logger.info('[INFO] allocate and attach successful')
        gwDpIp = err.get('PublicIp')
        if gwDpIp == None:
            logger.info("[ERROR]: gwDpIp is None")
            terminate('false', message)
            return
        else:
            logger.info("[INFO]: gwDpIp is %s", gwDpIp)


    #if we are here, then everything should have succeeded so
    #Call another lambda function that will check to see if the gateway is up
    #If up, it will configure the gateway. If not, it will sleep and recursively call itself until gateway is ready.

    parameters = {
                    "instance-id": instanceId,
                    "gateway-mgmt-ip": gwMgmtIp,
                    "gateway-dp-ip": gwDpIp,
                    "asg-name": message.get('AutoScalingGroupName'),
                    "asg-hookname" : message.get('LifecycleHookName'),
                    "portal-mgmt-ip": PortalMgmtIp,
                    "config-gw-func-name": config_gw_func,
                    "event-name": "gw-launch",
                    "lambda_bucket_name" : lambda_bucket_name
                 }
    invoke_response = lambda_client.invoke(FunctionName=config_gw_func,
                                            InvocationType='Event', Payload=json.dumps(parameters))
    if invoke_response.get('StatusCode') == 202:
        logger.info("[INFO]: Got OK from invoke lambda functions for launch. exiting...")
        return
    else:
        logger.info("[ERROR]: Something bad happened for launch. invoke_response = {}". format(invoke_response))
        terminate('false', message)
        return

###END LAUNCH CODE


def terminate_gw(event, message):

    global metadata
    global instanceId
    global gwDpIp
    global gwMgmtIp
    global subnetId
    global securityGroups
    global PortalMgmtIp
    global config_gw_func
    global lambda_bucket_name

    while True:
        try:
            interfaces_list = ec2_client.describe_network_interfaces(
                Filters=[
                {
                    'Name': 'attachment.instance-id',
                    'Values': [instanceId]
                }]
            )
        except:
            logger.info('[ERROR] Describe interfaces problem...error')
            terminate('false', message)
            return
        else:
            logger.info('[INFO] Got some interfaces...lets detach and delete')
            break

    if not interfaces_list:
        logger.info('[ERROR]: No interfaces listed for instance-id {}'.format(instanceId))
        terminate('false', message)
        return

    for interface in interfaces_list.get('NetworkInterfaces'):
        logger.info("[INTERFACE] {}".format(interface))
        if interface.get('Attachment').get('DeviceIndex') == 0:
            gwMgmtIp = interface.get('Association').get('PublicIp')
            continue
        elif interface.get('Attachment').get('DeviceIndex') == 1:
            gwDpIp = interface.get('Association').get('PublicIp')
            continue
    #if gwMgmtIp or gwDpIp == None:
    #    logger.info('[ERROR]: No gwmgmt or gwDpIp for interface {}'.format(interface))
    #    terminate('false', message)
    #    return
    #Now to call config gw to remove ip addres from portal and remove the metrics function and rule


    parameters = {
                    "instance-id": instanceId,
                    "gateway-mgmt-ip": gwMgmtIp,
                    "gateway-dp-ip": gwDpIp,
                    "asg-name": message.get('AutoScalingGroupName'),
                    "asg-hookname" : message.get('LifecycleHookName'),
                    "portal-mgmt-ip": PortalMgmtIp,
                    "config-gw-func-name": config_gw_func,
                    "event-name": "gw-terminate",
                    "lambda_bucket_name": lambda_bucket_name
                 }
    invoke_response = lambda_client.invoke(FunctionName=config_gw_func,
                                            InvocationType='RequestResponse', Payload=json.dumps(parameters))
    logger.info("[Invoke_response] {}". format(invoke_response))
    if invoke_response.get('StatusCode') == 200:
        err = botocore.response.StreamingBody.read(invoke_response['Payload'])
        if 'OK' in err:
            logger.info("[INFO]: Got OK from invoke lambda functions for terminate. Continue...")
        else:
            logger.info("[ERROR]: terminating gw returned error. invoke_response = {}". format(invoke_response))
            terminate('false', message)
            return
    else:
        logger.info("[ERROR]: Something bad happened for terminate. invoke_response = {}". format(invoke_response))
        terminate('false', message)
        return


    #Get a list of public IP addresses
    try:
        public_ip_list = ec2_client.describe_addresses(
                    Filters=[
                    {
                        'Name': 'instance-id',
                        'Values': [instanceId]
                    }]
        )
    except:
        logger.info("[ERROR]: Error getting public ip addresses")
        terminate('false', message)
        return

    for public_ip in public_ip_list.get('Addresses'):
        try:
            ec2_client.disassociate_address(AssociationId=public_ip.get('AssociationId'))
        except Exception as e:
            logger.info("[ERROR]: Error whilst disassociating elastic IP addresses")
            logger.info("[RESPONSE]: {}".format(e))
            terminate('false', message)
            return

        try:
            ec2_client.release_address(AllocationId=public_ip.get('AllocationId'))
        except Exception as e:
            logger.info("[ERROR]: Error whilst releasing elastic IP addresses")
            logger.info("[RESPONSE]: {}".format(e))
            terminate('false', message)
            return

    terminate('true', message)
    return




#    logger.info("[INFO]: Detaching and releasing network interface 1")
#
#    for interface in interfaces_list:
#        #Since we cannot detach interface index 0
#        if interface.get('Attachment').get('DeviceIndex') == 0:
#            continue
#        try:
#            ec2_client.detach_network_interface(
#                    AttachmentId=interface.get('Attachment').get('AttachmentId'), Force=True)
#        except:
#            logger.info("[ERROR]: Error whilst detaching network interface")
#            terminate('false', message)
#            return
#        else:
#            logger.info("[INFO]: Successfully detached network interface")
#
#        err = waitEniReady(interface.get('NetworkInterfaceId'))
#        if err == 'false':
#            logger.info("ERROR: Failure waiting for ENI to be ready before delete");
#            terminate('false', message);
#            return
#        try:
#            ec2_client.delete_network_interface(NetworkInterfaceId=interface.get('NetworkInterfaceId'))
#        except Exception as e:
#            logger.info("[ERROR]: Error deleting network interface id {}".format(interface.get('NetworkInterfaceId')))
#            logger.info("[Exception]: {}".format(e))
#            terminate('false', message)
#            return
#        else:
#            logger.info("[INFO]: Deleted network interface. Id: {}".format(interface.get('NetworkInterfaceId')))




def allocate_and_attach_eip(Id):
    logger.info("[INFO]: Entering allocateandattach def")
    eip_address_dict = ec2_client.describe_addresses()
    logger.info("[INFO]: eipaddressdict = {}".format(eip_address_dict))
    #List of IP addresses is not empty, so we may have an unassociated IP address?
    #eipList = eip_address_dict['Addresses']
    eip = allocateEip()
    #if not eipList:
    #    eip = allocateEip()
    #    if eip == 'false':
    #        return 'false'
    #else:
    #    #There are some elastic IPs floating around, so find if one of the is not associated with an instance
    #    logger.info("[INFO]: Found some EIPs")
    #    eip = getUnassociatedAddress(eipList)
    #    logger.info("[INFO]: eip var in else statement = {}".format(eip))
    #    #If the address is blank, then no unassociated addresses were found
    #    if eip is None:
    #        #So allocate an elastic ip
    #        eip = allocateEip()
    #        logger.info("[INFO]: did we enter the eip is none block? = {}".format(eip))
    #        if eip == 'false':
    #            logger.info("[INFO]: is eip == false? = {}".format(eip))
    #            return 'false'

    err = associateAddress(eip['AllocationId'], Id)
    logger.info("[INFO]: does err have an allocationID = {}".format(err))
    if err == 'false':
        logger.info("[INFO]: is err false = {}".format(err))
        return 'false'
    logger.info("[INFO]: what is the EIP? = {}".format(eip))
    return eip



#Create a network interface, pass the Interface ID to callback
def createEni(subnetId, securityGroups):
    try:
        nif = ec2.create_network_interface(SubnetId=subnetId, Groups=[securityGroups], Description="GPGateway DP")
    except Exception as e:
        logger.info("[ERROR]: ENI creation failed {}".format(e))
        return 'false'
    else:
        logger.info("INFO: ENI Created.\n")
        nif.modify_attribute(SourceDestCheck={'Value': False})
        while True:
            try:
                nif.reload()
            except:
                continue
            break

        response = nif.describe_attribute(Attribute='description')
        #Id = response['NetworkInterfaceId']
        Id = response.get('NetworkInterfaceId')
        if Id == None:
            logger.info("[ERROR]: CreateENI error. No network interface ID found")
            return 'false'
        else:
            return Id

def waitEniReady(Id):
    try:
        waiter = ec2_client.get_waiter('network_interface_available')
        waiter.wait(NetworkInterfaceIds=[Id], Filters= [{'Name' : 'status', 'Values': ['available']}])
    except Exception as e:
        logger.info("[ERROR]: ENI failed to reach desired state {}".format(e))
        return 'false'
    else:
       return 'true'


def attachEni(ec2Id, Id):
    try:
        err = ec2_client.attach_network_interface(NetworkInterfaceId=Id, InstanceId=ec2Id,DeviceIndex=1)
    except Exception as e:
            logger.info("[ERROR]: Failed to attach ENI to EC2 instance {}".format(e))
            return 'false'
    else:
        #logger.info("INFO: ENI attached EC2 instance\n")
        ec2_client.modify_network_interface_attribute(NetworkInterfaceId=Id,
                                                      Attachment={
                                                        'AttachmentId': err.get('AttachmentId'),
                                                        'DeleteOnTermination': True
        })
        return 'true'



def getUnassociatedAddress(eip_list):
    for eip_iter in eip_list:
        #is the public ip address associated with an instance id, if so don't use it
        if "InstanceId" not in eip_iter:
            address = eip_iter['PublicIp']
            if address:
                return  eip_iter #Means we found an address, so return the class
    return None


def allocateEip():
    try:
        eip = ec2_client.allocate_address(Domain='vpc')
    except Exception as e:
        logger.info("[ERROR]: Unable to allocate elastic IP {}".format(e))
        return 'false'
    else:
        #Associate eip with Instance ID
        logger.info("[INFO]: Allocated elastic IP\n")
        return eip

def associateAddress(AllocId, nifId):
    try:
        ec2_client.associate_address(AllocationId=AllocId, NetworkInterfaceId=nifId)
    except Exception as e:
        logger.info("[ERROR]: Unable to associate elastic IP {}".format(e))
        return 'false'
    else:
        return 'true'


#define a closure for easy termination later on
def terminate(success, asg_message):
    global instanceId

    if asg_message == None:
        return #this is not via an ASG event, but via CFT custom resource.
    else:
        #log that we're terminating and why
        if (success == 'false'):
            logging.error("[ERROR]: Lambda function reporting failure to AutoScaling with error:\n")
            result = "ABANDON"
        else:
            logger.info("[INFO]: Lambda function reporting success to AutoScaling.")
            result = "CONTINUE"

        #call autoscaling
        asg.complete_lifecycle_action(
            AutoScalingGroupName = asg_message['AutoScalingGroupName'],
            LifecycleHookName = asg_message['LifecycleHookName'],
            LifecycleActionToken = asg_message['LifecycleActionToken'],
            InstanceId = instanceId,
            LifecycleActionResult = result)
        return

