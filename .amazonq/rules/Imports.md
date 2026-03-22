when importing from aws-cdk-lib this is my perfered style

import {
aws_route53 as route53,
aws_iam as iam,
aws_certificatemanager as acm,
} from 'aws-cdk-lib';

import * as core from 'aws-cdk-lib'

import * from 'constructs' as constructs
