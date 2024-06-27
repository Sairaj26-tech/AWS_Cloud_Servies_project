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
import urllib
import ssl
import xml.etree.ElementTree as et
import time
import json

asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
lambda_client = boto3.client('lambda')
iam_client = boto3.client('iam')
events_client = boto3.client('events')

ctx = ssl.create_default_context()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ctx.check_hostname = False
    # No certificate check
ctx.verify_mode = ssl.CERT_NONE


#Some global variables....yikes!
asg_name = ""
asg_hookname = ""
instanceId = ""
gwMgmtIp = ""
gwDpIp = ""
PortalMgmtIp = ""
api_key = ""
gcontext = ""
job_id = ""
this_func_name = ""
lambda_function_arn = ""
lambda_bucket_name = ""

def config_gw_lambda_handler(event, context):
    global gcontext
    global api_key
    global gwMgmtIp
    global gwDpIp
    global PortalMgmtIp
    global job_id
    global asg_name
    global asg_hookname
    global instanceId
    global this_func_name
    global lambda_bucket_name

    logger.info('[INFO] Got event{}'.format(event))


    #If coming from AddENI then this is what the incoming event looks like:
    #{
    #  u'gateway-mgmt-ip': u'<public IP address>',
    #  u'instance-id': u'<ec2 instance id>',
    #  u'gateway-mgmt-ip': u'<gateway mgmt ip>,
    #  u'gateway-dp-ip': u'<gateway dataplane ip>,
    #  u'asg-name':u'<asg name>',
    #  u'asg-hookname': u'<asg LifecycleHookName>',
    #  u'portal-mgmt-ip: u'<mgmt IP of portal>',
    #  u'config-gw-func-name': u'<this functions name>',
    #  u'event-type' : u'gw-launch | gw-terminate'
    #  u'lambda_bucket_name': u'<lambda func bucket name>'
    #}



    #This is because lambda functions created in CFTs have misc identifiers
    #and by specifying a function name, you cannot launch multiple cft's at the same time
    this_func_name = event.get('config-gw-func-name')
    if this_func_name == None:
        logger.info("[ERROR]: Didn't get function name")
        return
    else:
        logger.info ("[INFO]: Function Name = {}".format(this_func_name))

    asg_name = event.get('asg-name')
    if asg_name == None:
        logger.info("[ERROR]: didn't get an asg name")
        #raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
        return

    asg_hookname = event.get('asg-hookname')
    if asg_hookname == None:
        logger.info("[ERROR]: didn't get an asg hookname")
        #raise Exception('Failed to get ASG hookname in : ', inspect.stack()[1][3])
        return

    gwMgmtIp = event.get('gateway-mgmt-ip')
    if gwMgmtIp == None:
        logger.info("[ERROR]: didn't get GW MGMT IP addresses")
        terminate('false')
        return

    gwDpIp = event.get('gateway-dp-ip')
    if gwDpIp == None:
        logger.info("[ERROR]: didn't get GW DP IP addresses")
        terminate('false')
        return

    PortalMgmtIp = event.get('portal-mgmt-ip')
    if PortalMgmtIp == None:
        logger.info("[ERROR]: didn't get Portal MGMT IP addresses")
        terminate('false')
        return

    instanceId = event.get('instance-id')
    if instanceId == None:
        logger.info("[ERROR]: didn't get Instance Id")
        #raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
        terminate('false')
        return

    lambda_bucket_name = event.get('lambda_bucket_name')
    if lambda_bucket_name == None:
        logger.info("[ERROR]: didn't get lambda bucket name")
        #raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
        terminate('false')
        return

    #The api key is pre-generated for  api_user/Pal0Alt0
    api_key = "LUFRPT11dEtJM0tPTzVHMnJhelpHUzVDN2k5clpTd0E9TUdXZUpoeG5LOVJXemxuVGZ6VGtKdWNlckU2d2RoK2U2RGRxVU1Oc3VJaz0="
    #Need this to by pass invalid certificate issue. Should try to fix this
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    event_type = event.get('event-name')
    if event_type == 'gw-terminate':
        logger.info("[INFO]: Got GW terminate event")
        return terminate_gw() #this is a synchronous call
    elif event_type == 'gw-launch':
        logger.info("[INFO]: Got gw launch event")
        config_gw(context)
        return
    else:
        logger.info("[ERROR]: What event is this?")
        terminate('false')
        return





## START LAUNCH CODE
def config_gw(context):
    global gcontext
    global api_key
    global gwMgmtIp
    global gwDpIp
    global PortalMgmtIp
    global job_id
    global asg_name
    global asg_hookname
    global instanceId
    global this_func_name
    global lambda_function_arn
    global lambda_bucket_name

    err = 'no'
    while (True):
        #err = check_fw_up()
        err = check_auto_commit_status()
        if err == 'cmd_error':
            logger.info("[ERROR]: Command error from fw")
            terminate('false')
            return
        elif err == 'no':
            logger.info("[INFO] FW is not up...yet")
            if (context.get_remaining_time_in_millis())/1000/60 < 2:
                logger.info("[INFO] have less than two minutes so call self")
                parameters ={
                    "instance-id": instanceId,
                    "gateway-mgmt-ip": gwMgmtIp,
                    "gateway-dp-ip": gwDpIp,
                    "asg-name": asg_name,
                    "asg-hookname" : asg_hookname,
                    "portal-mgmt-ip": PortalMgmtIp,
                    "config-gw-func-name": this_func_name,
                    "event-name": "gw-launch",
                    "lambda_bucket_name": lambda_bucket_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    #terminate lifecycle action
                    terminate('false')
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
                    "instance-id": instanceId,
                    "gateway-mgmt-ip": gwMgmtIp,
                    "gateway-dp-ip": gwDpIp,
                    "asg-name": asg_name,
                    "asg-hookname" : asg_hookname,
                    "portal-mgmt-ip": PortalMgmtIp,
                    "config-gw-func-name": this_func_name,
                    "event-name": "gw-launch",
                    "lambda_bucket_name": lambda_bucket_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    #terminate lifecycle action
                    terminate('false')
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
                    "instance-id": instanceId,
                    "gateway-mgmt-ip": gwMgmtIp,
                    "gateway-dp-ip": gwDpIp,
                    "asg-name": asg_name,
                    "asg-hookname" : asg_hookname,
                    "portal-mgmt-ip": PortalMgmtIp,
                    "config-gw-func-name": this_func_name,
                    "event-name": "gw-launch",
                    "lambda_bucket_name": lambda_bucket_name
                }
                invoke_response = lambda_client.invoke(FunctionName=this_func_name,
                                                        InvocationType='Event', Payload=json.dumps(parameters))
                if invoke_response.get('StatusCode') == 202:
                    logger.info("[INFO]: Got OK from invoke lambda functions. exiting...")
                    return
                else:
                    logger.info("[ERROR]: Something bad happened when calling lambda. invoke_response = {}". format(invoke_response))
                    #terminate lifecycle action
                    terminate('false')
                    return
            else:
                logger.info("[INFO]: FW is up and there is 3 or more minutes left. So exit the loop and config gw...finally!!")
                time.sleep(10) #sleep as there is a time gap between ready and all daemons up
                break

    #Config gw
    #once it is up, need to figure out how to update the portal with this EIP?????
    if (send_command('certificate') == 'false'):
        logger.info("[ERROR]: Generate certificate error")
        terminate('false')
        return
    else:
        logger.info("[INFO]: Generate certificate success")

    if(send_command('tls_profile') == 'false'):
        logger.info("[ERROR]: Could not update ssl/tls profile for gateway with generated cert")
        terminate('false')
        return
    else:
        logger.info("[INFO]: Updated ssl/tls profile with generated cert")

    if(send_command('commit_gw') == 'false'):
        logger.info("[ERROR]: Commit error")
        terminate('false')
        return
    else:
        logger.info("[INFO]: Commit successful")

    #Config portal to let it know there is a new gateway
    if(send_command('add_gw') == 'false'):
        logger.info("[ERROR]: Error in command to add gateway to portal")
        terminate('false')
        return
    else:
        logger.info("[INFO]: add gateway to portal successful")

    if(send_command('commit_portal') == 'false'):
        logger.info("[ERROR]: Commit portal job error")
        terminate('false')
        return
    else:
        logger.info("[INFO]: Commit portal successful")
        #terminate('true')

    logger.info("[INFO]: Getting Roles and stuff")
    #Create a lambda function that will run every minute and get metrics
    roles= iam_client.list_roles().get('Roles')

    for role_iter in roles:
        #logger.info("[INFO]: ROLE NAME: {}".format(role_iter.get('RoleName')))
        if 'LambdaExecutionRole' in role_iter.get('RoleName'):
            lambda_exec_role_name = role_iter.get('RoleName')
            logger.info('[INFO]: Found LambdaExecutionRole name')
            break
        else:
            continue

    if lambda_exec_role_name == None:
        logger.info('[ERROR]: Did not find LambdaExecutionRole name...quitting')
        terminate('false')
        return


    lambda_exec_role_arn = iam_client.get_role(RoleName=lambda_exec_role_name).get('Role').get('Arn')
    if lambda_exec_role_arn == None:
        logger.info("[ERROR]: Could not get lambda execution Role ARN")
        terminate('false')
        return


    logger.info("[INFO]: Creating lambda function")

    try:
        response = lambda_client.create_function(
            FunctionName='PushMetricsFor-'+instanceId,
            Runtime='python2.7',
            Role=lambda_exec_role_arn,
            Handler='push_metrics.gw_metrics_lambda_handler',
            Code={
                'S3Bucket': lambda_bucket_name,
                'S3Key': 'config_fw.zip'
            },
            Timeout=30
        )
    except Exception as e:
        logger.info("[ERROR]: Lambda function creation error")
        logger.info("[ERROR] {}".format(e))
        terminate('false')
        return
    else:
        logger.info("[INFO]: Successfully created lambda function!")
        lambda_function_arn = response.get('FunctionArn')



    #Now create a rule that runs every 1 minute and executes above lambda function
    try:
        response = events_client.put_rule(
            Name='PushMetricsRuleFor-'+instanceId,
            ScheduleExpression='rate(1 minute)',
            State='ENABLED'
        )
    except Exception as e:
        logger.info("[ERROR]: put_rule error")
        logger.info("[ERROR] {}".format(e))

        terminate('false')
        return
    else:
        logger.info("[INFO]: Successfully created rule!")
        events_source_arn = response.get('RuleArn')
        logger.info("[INFO]: source arn {}".format(events_source_arn))

    time.sleep(5)

    try:
        response = lambda_client.add_permission(
            FunctionName=lambda_function_arn,
            StatementId='PushMetricsFor-'+instanceId,
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=events_source_arn
        )
    except Exception as e:
        logger.info("[ERROR]: add permission error")
        logger.info("[ERROR] {}".format(e))
        terminate('false')
        return
    else:
        logger.info("[INFO]: Successfully added permission!")

    Input = {'gw-mgmt-ip': gwMgmtIp, 'asg-name': asg_name}
    try:
        response= events_client.put_targets(
            Rule='PushMetricsRuleFor-'+instanceId,
            Targets=
                [{
                    'Id': gwMgmtIp,
                    'Arn': lambda_function_arn,
                    'Input': json.dumps(Input)
                }]
        )
    except Exception as e:
        logger.info("[ERROR]: put_targets error")
        logger.info("[ERROR] {}".format(e))
        terminate('false')
        return
    else:
        logger.info("[INFO]: Successfully added target to rule!")
        if response.get('FailedEntryCount') > 0:
            logger.info('[ERROR]: Failed entry count is '+response.get('FailedEntryCount'))
            terminate('false')
            return
        else:
            terminate('true')
            return

###END LAUNCH CODE

def terminate_gw():
    global gcontext
    global api_key
    global gwMgmtIp
    global gwDpIp
    global PortalMgmtIp
    global job_id
    global asg_name
    global asg_hookname
    global instanceId
    global this_func_name
    global lambda_function_arn

    try:
        events_client.remove_targets(
            Rule='PushMetricsRuleFor-'+instanceId,
            Ids=[
                gwMgmtIp
            ]
        )
    except Exception as e:
        logger.info("[ERROR]: Error removing target")
        logger.info("[RESPONSE]: {}".format(e))
        #terminate('false')
        return 'ERROR'
    else:
        logger.info("[INFO]: Successfully removed target lambda function for rule")

    try:
        events_client.delete_rule(
             Name='PushMetricsRuleFor-'+instanceId
        )
    except Exception as e:
        logger.info("[ERROR]: Error removing rule")
        logger.info("[RESPONSE]: {}".format(e))
        #terminate('false')
        return 'ERROR'
    else:
        logger.info("[INFO]: Successfully deleted rule")

    try:
        lambda_client.delete_function(
             FunctionName='PushMetricsFor-'+instanceId
        )
    except Exception as e:
        logger.info("[ERROR]: Error deleting lambda function {}".format(lambda_function_arn))
        logger.info("[RESPONSE]: {}".format(e))
        #terminate('false')
        return 'ERROR'
    else:
        logger.info("[INFO]: Successfully deleted lambda function")


    #Delete gw from portal
    if(send_command('del_gw') == 'false'):
        logger.info("[ERROR]: Error in command to delete gateway from portal")
        #terminate('false')
        return 'ERROR'
    else:
        logger.info("[INFO]: delete gateway from portal successful")

    if(send_command('commit_portal') == 'false'):
        logger.info("[ERROR]: Commit portal job error")
        #terminate('false')
        return 'ERROR'
    else:
        logger.info("[INFO]: Commit portal successful")
        logger.info("[INFO]: Done deleting GW from the universe!")
        #terminate('true')
        return 'OK'


def send_command(cmd):
    global gwMgmtIp
    global gwDpIp
    global PortalMgmtIp
    global job_id
    global gconext
    global api_key
    gconext = ""

    job_id = ""

    if (cmd == 'commit_gw'):
        cmd_string = urllib.request.Request("https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key)
    elif (cmd == 'certificate'):
        cmd_string = urllib.request.Request("https://"+gwMgmtIp+"/api/?type=op&cmd=<request><certificate><generate><signed-by>root_CA</signed-by><certificate-name>gateway-cert</certificate-name><name>"+gwDpIp+"</name><algorithm><RSA><rsa-nbits>2048</rsa-nbits></RSA></algorithm></generate></certificate></request>&key="+api_key)
        cmdstringhttp = "https://"+gwMgmtIp+"/api/?type=op&cmd=<request><certificate><generate><signed-by>root_CA</signed-by><certificate-name>gateway-cert</certificate-name><name>"+gwDpIp+"</name><algorithm><RSA><rsa-nbits>2048</rsa-nbits></RSA></algorithm></generate></certificate></request>&key="+api_key
    elif (cmd == 'tls_profile'):
        cmd_string = urllib.request.Request("https://"+gwMgmtIp+"/api/?type=config&action=set&xpath=/config/shared/ssl-tls-service-profile/entry[@name='gateway-ssl-tls']&element=<certificate>gateway-cert</certificate>&key="+api_key)
    elif(cmd == 'add_gw'):
        cmd_string = urllib.request.Request("https://"+PortalMgmtIp+"/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='portal']/client-config/configs/entry[@name='default']/gateways/external/list/entry[@name='"+gwDpIp+"']&element=<ip><ipv4>"+gwDpIp+"</ipv4></ip><priority-rule><entry%20name='Any'><priority>1</priority></entry></priority-rule><manual>yes</manual>&key="+api_key)
        cmdstringhttp = "https://"+PortalMgmtIp+"/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='portal']/client-config/configs/entry[@name='default']/gateways/external/list/entry[@name='"+gwDpIp+"']&element=<ip><ipv4>"+gwDpIp+"</ipv4></ip><priority-rule><entry%20name='Any'><priority>1</priority></entry></priority-rule><manual>yes</manual>&key="+api_key
    elif(cmd == 'del_gw'):
        cmd_string = urllib.request.Request("https://"+PortalMgmtIp+"/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='portal']/client-config/configs/entry[@name='default']/gateways/external/list/entry[@name='"+gwDpIp+"']&key="+api_key)
    elif (cmd == 'commit_portal'):
        cmd_string = urllib.request.Request("https://"+PortalMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key)

    else:
        logger.info("[ERROR]: Unknown command")
        return 'false'

    logger.info('[INFO]: Sending command in sendcommandfunc: %s', cmd_string)
    try:
        
        response = urllib.request.urlopen(cmd_string, data=None, context=ctx, timeout=5).read()
        #Now we do stuff to the gw

        logger.info("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
        logger.info("[ERROR]: Excpetion in send command:")
        logger.info("[ERROR] {}".format(e))
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

    if(cmd == 'commit_gw' or cmd == 'commit_portal'):
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
        if cmd == 'commit_gw':
            cmd_string = "https://"+gwMgmtIp+"/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
        elif cmd == 'commit_portal':
            cmd_string = "https://"+PortalMgmtIp+"/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
        else:
            logger.info("[ERROR]: send command not commit gw or commit portal so error!")
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
    global gwMgmtIp
    global api_key
    cmd = urllib.request.Request("https://"+gwMgmtIp+"/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key="+api_key)
    #cmd = "https://"+gwMgmtIp+"/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key="+api_key
    #Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command in checkfwfunc: %s', cmd)
    try:
        response = urllib.request.urlopen(cmd, data=None, context=ctx, timeout=5).read()
        #response = urllib.request.Request(cmd)
        #http = urllib3.PoolManager()
        #response = http.request('GET', cmd, timeout=5, verify=False)
        #response = urllib.request.urlopen(cmd, context=gcontext, timeout=5).read()
        print(("[INFO]: Response Value: {}".format(response)))
        #Now we do stuff to the gw
    except urllib.error.URLError as e: 
        logger.info("[INFO]: No response from FW. So maybe not up! without cache {}".format(e))
        return 'no'
        #sleep and check again?
    else:
        logger.info("[INFO]: FW is up!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        #raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
        return 'cmd_error'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        #raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
        return 'cmd_error'

    if resp_header.attrib['status'] == 'success':
    #The fw responded with a successful command execution. So is it ready?
        for element in resp_header:
            if element.text.rstrip() == 'yes':
            #Call config gw command?
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
    global gwMgmtIp
    global api_key

    job_id = '1' #auto commit job id is always 1
    cmd = urllib.request.Request("https://" + gwMgmtIp + "/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key=" + api_key)
    # cmd = "https://"+gwMgmtIp+"/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
    #Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command in checkautofunc: %s', cmd)
    try:
        response = urllib.request.urlopen(cmd, data=None, context=ctx, timeout=5).read()
        #response = urllib.request.Request(cmd)
        #http = urllib3.PoolManager()
        #response = http.request('GET', cmd, timeout=5, verify=False)
        #response = urllib.request.urlopen(cmd, context=gcontext, timeout=5).read()
        #logger.info('[INFO]: Response Value in workaround: {}'.format(response))
        #Now we do stuff to the gw
    except urllib.error.URLError as e: 
        logger.info("[INFO]: No response from FW in workaround. So maybe not up! without cache {}".format(e))
        return 'no'
        #sleep and check again?
    else:
        logger.info("[INFO]: FW is up in workaround!!")

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




#define a closure for easy termination later on
def terminate(success):
    global asg_name
    global asg_hookname
    global instanceId

    #log that we're terminating and why
    if (success == 'false'):
        logging.error("[ERROR]: Lambda function reporting failure to AutoScaling with error\n")
        result = "ABANDON"
    else:
        logger.info("[INFO]: Lambda function reporting success to AutoScaling.")
        result = "CONTINUE"

    logger.info("[INFO]: asg_name: {}, asg_hookname: {}, instanceId: {}".format(asg_name, asg_hookname, instanceId))
    #call autoscaling
    asg.complete_lifecycle_action(
        AutoScalingGroupName = asg_name,
        LifecycleHookName = asg_hookname,
        InstanceId = instanceId,
        LifecycleActionResult = result)
    return

