# Verify a synthetic metadata session and offline provider-evidence parser

```sh
python3 lab.py test SAF-K8S-0704-004 --docker-context desktop-linux
```

Two owned services return a public marker. The session-required service rejects
missing and expired fixture sessions. A separate synthetic inventory exercises
classification of effective, declared, pending and disabled endpoint settings.

The two services are case-owned synthetic routes using a custom fixture session
header; they are not EC2 IMDS endpoints and do not implement the IMDSv2 token
protocol. Effective cloud node settings, launch mechanisms, runtime reachability
and provider support require separate evidence.

## Offline EC2 evidence-shape supplement

The fifth check reads a fixed static AWS-shaped `DescribeInstances` JSON fixture.
It preserves the four synthetic service and inventory checks, selects the fixture
record only by the expected `InstanceId`, and passes the effective
`MetadataOptions` fields through the existing `current_result` classifier. The fixture compares one intended launch-template version against
three applied/pending instance observations and one mismatched instance ID:
effective required tokens match, an effective optional-token value remains
drift despite the template declaring required, pending stays unverified, and
an unrelated instance is unverified.

The fixture records `HttpEndpoint`, `HttpTokens`, `State`, `HttpProtocolIpv6`,
`HttpPutResponseHopLimit`, and instance-tag access. It checks that the hop
limit is an integer within the documented API range and records the effective
value; it does not set a universal hop-limit policy or infer client safety from
the fixture value. No AWS API or SDK call, cloud account, instance metadata
endpoint, or credential is used. This static parser example does not replace the
open deployed-provider evidence requirement.

The shape follows the EC2 [DescribeInstances response model](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
and [InstanceMetadataOptionsResponse](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceMetadataOptionsResponse.html)
for API version `2016-11-15`. The launch-template field follows the
[CloudFormation LaunchTemplate MetadataOptions schema](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-metadataoptions.html).
AWS's [metadata-options precedence guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
explains why effective instance observations must be considered alongside
declared template intent.

The five-check receipt combines four checks against case-owned synthetic services
and inventory with one offline static evidence-parser check. None is an observation
of a real EC2 instance or another cloud provider. Verify effective settings,
launch precedence, supported clients, and provider-specific protections separately
for each deployed node pool.
