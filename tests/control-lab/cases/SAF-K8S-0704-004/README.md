# Verify a synthetic metadata session and inventory evidence gate

```sh
python3 lab.py test SAF-K8S-0704-004 --docker-context desktop-linux
```

Two owned services return a public marker. The session-required service rejects
missing and expired fixture sessions. A separate synthetic inventory exercises
classification of effective, declared, pending and disabled endpoint settings.

The services use synthetic routes and session data. Effective cloud node
settings, launch mechanisms, runtime reachability and provider support require
separate evidence.

## Offline EC2 evidence-shape supplement

This scratch candidate preserves the four published checks and adds one
offline assertion. It reads a fixed synthetic `DescribeInstances`-shaped JSON
file, selects records only by the expected `InstanceId`, and passes the
effective `MetadataOptions` fields through the existing `current_result`
classifier. The fixture compares one intended launch-template version against
three applied/pending instance observations and one mismatched instance ID:
effective required tokens match, an effective optional-token value remains
drift despite the template declaring required, pending stays unverified, and
an unrelated instance is unverified.

The fixture records `HttpEndpoint`, `HttpTokens`, `State`, `HttpProtocolIpv6`,
`HttpPutResponseHopLimit`, and instance-tag access. It checks that the hop
limit is an integer within the documented API range and records the effective
value; it does not set a universal hop-limit policy or infer client safety from
the fixture value. No AWS API, SDK call, cloud account, instance metadata
endpoint, or credential is used. This parser/example does not replace the
open deployed-provider evidence requirement.

The shape follows the EC2 [DescribeInstances response model](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
and [InstanceMetadataOptionsResponse](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceMetadataOptionsResponse.html)
for API version `2016-11-15`. The launch-template field follows the
[CloudFormation LaunchTemplate MetadataOptions schema](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-metadataoptions.html).
AWS's [metadata-options precedence guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
explains why effective instance observations must be considered alongside
declared template intent.

Expected receipt count: five total, with the four published live checks
unchanged and one additive offline evidence-gate check.
