#
# Incidence Response

So, we know there is an issue and we need to respond. We have to make some assumptions here, as the we don&#39;t have a legal department or other parts of the equation that would be an enterprise. The first assumption is that we are only moderately concerned attribution, which may seem like an odd statement, but most companies aren&#39;t interested in attribution, as it is hard to do and offers little in the way return on investment. Secondly, we are assuming that our make-believe enterprise doesn&#39;t have to worry about moving data across country lines or other HR issues that would be specific to different regions of the world.

## **Setup**

So, we know we have an issue, the first thing we need to do is decide how we want to deal with it. In this case we are going to assume that the enterprise is not interested in collecting data about bad actors. The two options are 1. Stop the bad actor, or 2. Observe the bad actor, and learn about them. As stated, we are going to follow option 1 and simply stop the attacker. In this case we have a comprised account and external SSH access.

We need to decide what to do fist. If we decide we want to stop the bad actor, we need to look at the different avenues of access. In this case the actor has access to your account and one of your instances. In this case, we should turn off account first in an effort to stop the bad actor from building new instances.

Step 1 – Removal of Control

Browse to the AWS Console and go to the IAM service

![Picture1](img/Picture1.png)

- Once there click the Users link on the left. This will bring you to the Users Screen.

![Picture2](img/Picture2.png)

-  You will note that the access Key age is today, not a good sign, as it means that someone has just created access. Click on the user that starts with the word &quot;Module-&quot;

![Picture3](img/Picture3.png)

- Here we can see that this use has Admin access. If we need to maintain this user for investigative purposes, we can simply remove the access that it has by remove the Policies that it has associated with it and changing the credentials. If a User that is associated with application is compromised, we may only want to change the access keys and password. We do this by clicking on the Security Credentials tab.

![Picture4](img/Picture4.png)

- Here we can see that the use has been used recently. We also have the option to remove the access the they may have, by clicking the &quot;X&quot; near make inactive. In a real world scenario it may be a very good choice to click the &quot;Make Inactive&quot; button, if the comprised user has existed for a long period of time and developers may have used these credentials. You will also note that this user, is only able to login into the API, not the console, as the console password says that it is disabled. Also please review is the user has an SSH key. If they do this would mean that the bad actor could infect any products that this user has the ability to touch.

## **SSH Traffic from the Outside**

Second, we need to correct the SSH traffic to a server that is on the open network. We have a multitude of choices to do this. The easiest two are:

1. Changing the subnet in the SSH line, in the security groups to remove the ability of the general internet to connect to this port.

2. Remove the SSH line altogether and use SSM to manage the system going forward, or build a bastion host.

**Tip** : Remember, if there is already an SSH connection to a server active, you will also have to place a NACL in place, break the session.

### **Breadcrumbs**

- Find the Security group/s that allow conventional SSH port: 22 (TCP)
- Figure out the event format

**Note** : In a real environment, SSH may be running on different ports, so you might need some protocol analysis as well. Additionally, in some cases you might want to use different log sources, such as SSH logs themselves, if available - or use them in combination with other types of logs. The amount of data that is found in the flow logs can be very close between a successful and an unsuccessful connection, so it&#39;s not always reliable - but we also don&#39;t have perfect logging, and it&#39;s often sufficient. Remember to think out of the box!

## **Ok, you know how to do it by hand…**

### **Scenario (This is the hard part)**

In the real world you will need to do all of the above, over the course of half a second. You need to be able to automate all of it and do it quickly. In the real world, many of the actions that you would expect to do are pre written for you in things like CloudCustodian or Warden. Warden is described in another session here at re:inforce.

### **What to do**

### In this exercise you will build two simple lambda functions to correct the above issues and a step function to control them. The goal of this exercise is not to make a full application that you can deploy to a production environment but rather to show to build a system that can help you as the student understand the possibilities both good and bad.

### Step one:

Build out your work flow. The below is a step function that I used for a webinar, earlier this year. If you take a look at the parts, you can see that it is broken up into steps, each of these steps calls another step. Notice in the below step function that the &quot;Resource&quot; in each section is pointing to the ARN of a lambda function. There is also a &quot;Next&quot; item and it points to another step in the function.
There is also a try/catch portion of each step, that reviews the output of the step function and pushes the function to solve the issue it encountered. There is also a section called &quot;IngestionType&quot;, which looks at the &quot;ResultsPath&quot; and evaluates the answers to switch over to a new steps. Also be aware that there is no order in the statement, it starts with the &quot;StartAt&quot; statement says it should, and ends at the &quot;EndState&quot; step.

### An example Step function:

{

  &quot;Comment&quot;: &quot;Remediation\_Machine&quot;,

  &quot;States&quot;: {

      &quot;Failed&quot;: {

          &quot;Type&quot;: &quot;Pass&quot;,

          &quot;Next&quot;: &quot;EndState&quot;

      },

      &quot;IngestionAction&quot;: {

          &quot;Resource&quot;: &quot;arn:aws:lambda:us-east-2:99999999999:function:CloudWatcherCore&quot;,

          &quot;ResultPath&quot;: &quot;$.CloudWatcherCore&quot;,

          &quot;InputPath&quot;: &quot;$&quot;,

          &quot;TimeoutSeconds&quot;: 86400,

          &quot;HeartbeatSeconds&quot;: 60,

          &quot;Next&quot;: &quot;IngestionType&quot;,

          &quot;Type&quot;: &quot;Task&quot;,

          &quot;Retry&quot;: [

              {

                  &quot;ErrorEquals&quot;: [&quot;States.ALL&quot;],

                  &quot;IntervalSeconds&quot;: 10,

                  &quot;MaxAttempts&quot;: 5,

                  &quot;BackoffRate&quot;: 2

              }

          ],

          &quot;Catch&quot;: [ {

              &quot;ErrorEquals&quot;: [&quot;States.ALL&quot;],

              &quot;Next&quot;: &quot;Failed&quot;,

              &quot;ResultPath&quot;: &quot;$.CreateSnapshot.error&quot;

          } ]

      },

      &quot;IngestionType&quot;: {

        &quot;Type&quot;: &quot;Choice&quot;,

        &quot;Choices&quot;: [

          {

            &quot;Variable&quot;: &quot;$.CloudWatcherCore&quot;,

            &quot;StringEquals&quot;: &quot;EmergencyActionIfrastructure&quot;,

            &quot;Next&quot;: &quot;EmergencyActionIfrastructure&quot;

          },

          {

            &quot;Variable&quot;: &quot;$.CloudWatcherCore&quot;,

            &quot;StringEquals&quot;: &quot;EmergencyActionAccount&quot;,

            &quot;Next&quot;: &quot;EmergencyActionAccount&quot;

          },

          {

            &quot;Variable&quot;: &quot;$.CloudWatcherCore&quot;,

            &quot;StringEquals&quot;: &quot;EmergencyActionApplication&quot;,

            &quot;Next&quot;: &quot;EmergencyActionApplication&quot;

          }

        ],

        &quot;Default&quot;: &quot;EndState&quot;

      },

      &quot;EndState&quot;: {

          &quot;End&quot;: true,

          &quot;Type&quot;: &quot;Pass&quot;

      }

  },

  &quot;StartAt&quot;: &quot;IngestionAction&quot;

}

Step 1:

###         In the above Step function, decide how you want to do first.

### **Breadcrumbs**

As stated above, maybe we should take care of the account breach first. There is a way to do that in an automatically.

Review:

[https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.delete_user)

Example Lambda Script:

import boto3

def lambda\_handler(event, context):

    iam = client(&#39;iam&#39;)

    ec2 = client(&#39;ec2&#39;)

        iam.delete\_access\_key(

        AccessKeyId=event[&quot;ACCESS\_KEY\_ID&quot;],

        UserName=event[&quot;IAM\_USER\_NAME&quot;]

    )







Step 2.

 Work through the need for a networking change. In a datacenter this could take a significant amount of time. This will be much quicker. How do we correct the Security Group? We use a similar Lambda function to that.

### **Breadcrumbs**

As stated above, maybe we should take care of the account breach first. There is a way to do that in an automatically.

Review:

[https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.delete_user)

Example Lambda Script:

from \_\_future\_\_ import print\_function

import json, urllib2, boto3

def lambda\_handler(event, context):

    response = urllib2.urlopen(&#39;https://ip-ranges.amazonaws.com/ip-ranges.json&#39;)

    json\_data = json.loads(response.read())

    new\_ip\_ranges = [x[&#39;ip\_prefix&#39;] for x in json\_data[&#39;prefixes&#39;] if x[&#39;service&#39;] == &#39;CLOUDFRONT&#39; ]

    #print(new\_ip\_ranges)

    ec2 = boto3.resource(&#39;ec2&#39;)

    security\_group = ec2.SecurityGroup(&#39;sg-6rrrrr10&#39;)

    current\_ips = security\_group.ip\_permissions

    if len(current\_ips) == 0:

        current\_ip\_ranges = []

    else:

        current\_ip\_ranges = [x[&#39;cidrip&#39;] for x in current\_ips[0][&#39;ipranges&#39;] ]

    print(current\_ip\_ranges)

    params\_dict = {

        u&#39;PrefixListIds&#39;: [],

        u&#39;FromPort&#39;: 80,

        u&#39;IpRanges&#39;: [],

        u&#39;ToPort&#39;: 443,

        u&#39;IpProtocol&#39;: &#39;tcp&#39;,

        u&#39;UserIdGroupPairs&#39;: []

    }

    authorize\_dict = params\_dict.copy()

    for ip in new\_ip\_ranges:

        if ip not in current\_ip\_ranges:

            authorize\_dict[&#39;IpRanges&#39;].append({u&#39;CidrIp&#39;: ip})

    revoke\_dict = params\_dict.copy()

    for ip in current\_ip\_ranges:

        if ip not in new\_ip\_ranges:

            revoke\_dict[&#39;IpRanges&#39;].append({u&#39;CidrIp&#39;: ip})

    print(&quot;the following new ip addresses will be added:&quot;)

    print(authorize\_dict[&#39;IpRanges&#39;])

    print(&quot;the following new ip addresses will be removed:&quot;)

    print(revoke\_dict[&#39;IpRanges&#39;])

    security\_group.revoke\_ingress(IpPermissions=[revoke\_dict])

    security\_group.authorize\_ingress(IpPermissions=[authorize\_dict])

    return {&#39;authorized&#39;: authorize\_dict, &#39;revoked&#39;: revoke\_dict}

Step 3.

Once you have built and tested the two above Lambda functions. Once those functions are running you will need to incorporate them into the above Step Function in your lab. This part should be straight forward.

Step 4.

To test this step function, you need to fire it in some way. The best way to test this is add a cloud watch rule.



This example show the connection for the Step function from above and the needed events in CloudTrail. We can expand this pattern to include many items that are concerning. If we choose

![Picture5](img/Picture5.png)

to we can build StepFunctions to deal with other Cloud trail event s that we deem to be untoward.

Once we have completed this step, this lab is complete, and you should have the basic skills that will allow you build a system, to response to threat in your application.
