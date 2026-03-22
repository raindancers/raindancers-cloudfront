import json
import boto3
from typing import Any, Dict, List

wafv2 = boto3.client('wafv2', region_name='us-east-1')

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Custom resource handler for creating WAF WebACLs in us-east-1.
    """
    print(f"Event: {json.dumps(event)}")
    
    try:
        request_type = event['RequestType']
        props = event['ResourceProperties']
        
        name = props['Name']
        enable_managed_rules = props.get('EnableManagedRules', 'true')
        # Convert string to boolean
        if isinstance(enable_managed_rules, str):
            enable_managed_rules = enable_managed_rules.lower() == 'true'
        rate_limit = int(props.get('RateLimit', 2000))
        path_rate_limits_str = props.get('PathRateLimits', '[]')
        path_rate_limits = json.loads(path_rate_limits_str) if isinstance(path_rate_limits_str, str) else path_rate_limits_str
        allowed_countries = props.get('AllowedCountries', [])
        blocked_countries = props.get('BlockedCountries', [])
        
        print(f"Processing {request_type} for WebACL: {name}")
        
        if request_type == 'Create':
            return create_webacl(name, enable_managed_rules, rate_limit, path_rate_limits, allowed_countries, blocked_countries)
        elif request_type == 'Update':
            webacl_id = event['PhysicalResourceId']
            return update_webacl(webacl_id, name, enable_managed_rules, rate_limit, path_rate_limits, allowed_countries, blocked_countries)
        elif request_type == 'Delete':
            webacl_id = event['PhysicalResourceId']
            return delete_webacl(webacl_id, name)
        
        return {
            'PhysicalResourceId': event.get('PhysicalResourceId', 'unknown'),
            'Data': {}
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

def create_webacl(name: str, enable_managed_rules: bool, rate_limit: int, path_rate_limits: List[Dict[str, Any]], allowed_countries: List[str], blocked_countries: List[str]) -> Dict[str, Any]:
    """Create a WAF WebACL."""
    
    rules = build_rules(enable_managed_rules, rate_limit, path_rate_limits, allowed_countries, blocked_countries)
    
    print(f"Creating WebACL with {len(rules)} rules")
    
    response = wafv2.create_web_acl(
        Name=name,
        Scope='CLOUDFRONT',
        DefaultAction={'Allow': {}},
        Rules=rules,
        VisibilityConfig={
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name
        }
    )
    
    webacl_arn = response['Summary']['ARN']
    webacl_id = response['Summary']['Id']
    
    print(f"WebACL created: {webacl_arn}")
    
    return {
        'PhysicalResourceId': webacl_id,
        'Data': {
            'WebAclArn': webacl_arn,
            'WebAclId': webacl_id
        }
    }

def update_webacl(webacl_id: str, name: str, enable_managed_rules: bool, rate_limit: int, path_rate_limits: List[Dict[str, Any]], allowed_countries: List[str], blocked_countries: List[str]) -> Dict[str, Any]:
    """Update a WAF WebACL."""
    
    # Get current WebACL to get lock token
    response = wafv2.get_web_acl(
        Name=name,
        Scope='CLOUDFRONT',
        Id=webacl_id
    )
    
    lock_token = response['LockToken']
    webacl_arn = response['WebACL']['ARN']
    
    rules = build_rules(enable_managed_rules, rate_limit, path_rate_limits, allowed_countries, blocked_countries)
    
    print(f"Updating WebACL with {len(rules)} rules")
    
    wafv2.update_web_acl(
        Name=name,
        Scope='CLOUDFRONT',
        Id=webacl_id,
        DefaultAction={'Allow': {}},
        Rules=rules,
        VisibilityConfig={
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name
        },
        LockToken=lock_token
    )
    
    print(f"WebACL updated: {webacl_arn}")
    
    return {
        'PhysicalResourceId': webacl_id,
        'Data': {
            'WebAclArn': webacl_arn,
            'WebAclId': webacl_id
        }
    }

def delete_webacl(webacl_id: str, name: str) -> Dict[str, Any]:
    """Delete a WAF WebACL."""
    
    try:
        # Get current WebACL to get lock token
        response = wafv2.get_web_acl(
            Name=name,
            Scope='CLOUDFRONT',
            Id=webacl_id
        )
        
        lock_token = response['LockToken']
        
        wafv2.delete_web_acl(
            Name=name,
            Scope='CLOUDFRONT',
            Id=webacl_id,
            LockToken=lock_token
        )
        
        print(f"WebACL deleted: {webacl_id}")
    except wafv2.exceptions.WAFNonexistentItemException:
        print(f"WebACL not found: {webacl_id}")
    except Exception as e:
        print(f"Error deleting WebACL: {e}")
        import traceback
        traceback.print_exc()
        # Don't raise on delete - best effort cleanup
    
    return {
        'PhysicalResourceId': webacl_id,
        'Data': {}
    }

def build_rules(enable_managed_rules: bool, rate_limit: int, path_rate_limits: List[Dict[str, Any]], allowed_countries: List[str], blocked_countries: List[str]) -> List[Dict[str, Any]]:
    """Build the rules list for the WebACL."""
    
    rules = []
    priority = 0
    
    # Geo-blocking rules (highest priority)
    if allowed_countries:
        print(f"Adding geo-allow rule for countries: {allowed_countries}")
        rules.append({
            'Name': 'GeoAllowRule',
            'Priority': priority,
            'Statement': {
                'NotStatement': {
                    'Statement': {
                        'GeoMatchStatement': {
                            'CountryCodes': allowed_countries
                        }
                    }
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'GeoAllowRule'
            }
        })
        priority += 1
    
    if blocked_countries:
        print(f"Adding geo-block rule for countries: {blocked_countries}")
        rules.append({
            'Name': 'GeoBlockRule',
            'Priority': priority,
            'Statement': {
                'GeoMatchStatement': {
                    'CountryCodes': blocked_countries
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'GeoBlockRule'
            }
        })
        priority += 1
    
    # Path-specific rate limiting rules (before general rate limit)
    for idx, path_limit in enumerate(path_rate_limits):
        path = path_limit['path']
        limit = int(path_limit['rateLimit'])
        rule_name = path_limit.get('name', f"PathRateLimit{idx}")
        
        print(f"Adding path-specific rate limit: {path} = {limit} req/5min")
        
        rules.append({
            'Name': rule_name,
            'Priority': priority,
            'Statement': {
                'RateBasedStatement': {
                    'Limit': limit,
                    'AggregateKeyType': 'IP',
                    'ScopeDownStatement': {
                        'ByteMatchStatement': {
                            'SearchString': path,
                            'FieldToMatch': {
                                'UriPath': {}
                            },
                            'TextTransformations': [{
                                'Priority': 0,
                                'Type': 'NONE'
                            }],
                            'PositionalConstraint': 'STARTS_WITH' if not '*' in path else 'CONTAINS'
                        }
                    }
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_name
            }
        })
        priority += 1
    
    # General rate limiting rule
    rules.append({
        'Name': 'RateLimitRule',
        'Priority': priority,
        'Statement': {
            'RateBasedStatement': {
                'Limit': rate_limit,
                'AggregateKeyType': 'IP'
            }
        },
        'Action': {
            'Block': {}
        },
        'VisibilityConfig': {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': 'RateLimitRule'
        }
    })
    priority += 1
    
    if enable_managed_rules:
        # Core Rule Set
        rules.append({
            'Name': 'AWSManagedRulesCommonRuleSet',
            'Priority': priority,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesCommonRuleSet'
                }
            },
            'OverrideAction': {
                'None': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'AWSManagedRulesCommonRuleSet'
            }
        })
        priority += 1
        
        # Known Bad Inputs
        rules.append({
            'Name': 'AWSManagedRulesKnownBadInputsRuleSet',
            'Priority': priority,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesKnownBadInputsRuleSet'
                }
            },
            'OverrideAction': {
                'None': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'AWSManagedRulesKnownBadInputsRuleSet'
            }
        })
        priority += 1
        
        # Amazon IP Reputation List
        rules.append({
            'Name': 'AWSManagedRulesAmazonIpReputationList',
            'Priority': priority,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesAmazonIpReputationList'
                }
            },
            'OverrideAction': {
                'None': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'AWSManagedRulesAmazonIpReputationList'
            }
        })
        priority += 1
        
        # Anonymous IP List
        rules.append({
            'Name': 'AWSManagedRulesAnonymousIpList',
            'Priority': priority,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesAnonymousIpList'
                }
            },
            'OverrideAction': {
                'None': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'AWSManagedRulesAnonymousIpList'
            }
        })
        priority += 1
    
    return rules
