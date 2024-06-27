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
import urllib.request, urllib.error, urllib.parse
import ssl
import xml.etree.ElementTree as et
import datetime


logger = logging.getLogger()
logger.setLevel(logging.INFO)


cw_client = boto3.client('cloudwatch')

def gw_metrics_lambda_handler(event, context):
    logger.info('[INFO]: got event{}'.format(event))


    gwMgmtIp = event.get('gw-mgmt-ip')
    if gwMgmtIp == None:
        logger.info("[ERROR]: Didn't get GW MGMT IP in event")
        raise Exception("[ERROR]: Didn't get GW MGMT IP in event")

    asg_name = event.get('asg-name')
    if asg_name == None:
        logger.info("[ERROR]: Didn't get auto scaling group name in event")
        raise Exception("[ERROR]: Didn't get auto scaling group name in event")

    #The api key is pre-generated for  api_user/Pal0Alt0
    api_key = "LUFRPT11dEtJM0tPTzVHMnJhelpHUzVDN2k5clpTd0E9TUdXZUpoeG5LOVJXemxuVGZ6VGtKdWNlckU2d2RoK2U2RGRxVU1Oc3VJaz0="
    #Need this to by pass invalid certificate issue. Should try to fix this
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    show_session_cmd = "https://"+gwMgmtIp+"/api/?type=op&cmd=<show><session><info/></session></show>&key="+api_key
    logger.info('[INFO]: Sending command: %s', show_session_cmd)
    try:
        response = urllib.request.urlopen(show_session_cmd, context=gcontext, timeout=5).read()
        #logger.info("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.info("[ERROR]: Something bad happened when sending command")
         logger.info("[RESPONSE]: {}".format(e))
         raise Exception("[ERROR]: Something bad happened when sending command")
    else:
        logger.info("[INFO]: Got a (good?) response from command")

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from GW")
        raise Exception("[ERROR]: Didn't get a valid response from GW")

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        raise Exception("[ERROR]: Got an error for the command")

    if resp_header.attrib['status'] == 'success':
    #The fw responded with a successful command execution.
        logger.info("[INFO]: Successfully executed command")
        #Now to find number of active sessions
        result = resp_header.findall('.//result')[0]
        #Iterate through all the results tag
        for c in result:
            if 'num-active' in c.tag:
                num_active_sessions = c.text
                timestamp = datetime.datetime.utcnow()
                break

        logger.info("[INFO]: num_active_sessions: {}".format(int(num_active_sessions)))
#The namespace and metric name is hard-coded, but could be passed in
        try:
            response = cw_client.put_metric_data(
                Namespace = 'GPGatewayMetrics',
                MetricData=[{
                        'MetricName': 'ActiveSessions',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': int(num_active_sessions),
                        'Unit': 'Count'
                    }]
            )
        except Exception as e:
            logger.info("[ERROR]: Error when publishing metric data")
            logger.info("[ERROR] {}".format(e))
            raise Exception("Error when publishing metric data {}".format(e))
        else:
            logger.info("[INFO]: Published metric for {}".format(gwMgmtIp))
            return
