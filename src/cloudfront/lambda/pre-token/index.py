def handler(event, context):
    groups = event['request']['groupConfiguration']['groupsToOverride']
    event['response']['claimsAndScopeOverrideDetails'] = {
        'idTokenGeneration': {
            'claimsToAddOrOverride': {
                'roles': groups,
                'https://aws.amazon.com/tags/principal_tags/Claims': ':' + ':'.join(groups) + ':',
            }
        }
    }
    return event
