"""
DynamoDB item model and accessors for the SCIM-provisioned directory mirror.

Single table, prefix-discriminated:
  * User item:  pk = sk = USER#<externalId>
      scimId, externalId, userName, displayName, active, groupIds(set), updatedAt
      GSI1 (gsi1pk = SCIMID#<scimId>)         -> resolve /Users/{id} without scan
      GSI2 (gsi2pk = USERNAME#<lower(userName)>) -> userName eq filter
  * Group item: pk = sk = GROUP#<groupId>
      groupId, displayName, updatedAt

The consumer hot path is a single GetItem on pk=USER#<externalId> returning
`active` + `groupIds`.
"""

import datetime
import os

import boto3
from boto3.dynamodb.conditions import Key


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _table():
    return boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])


def user_pk(external_id):
    return f'USER#{external_id}'


def group_pk(group_id):
    return f'GROUP#{group_id}'


# ---------------------------------------------------------------- users

def put_user(external_id, scim_id, user_name, display_name, active, group_ids):
    item = {
        'pk': user_pk(external_id),
        'sk': user_pk(external_id),
        'scimId': scim_id,
        'externalId': external_id,
        'userName': user_name,
        'displayName': display_name or '',
        'active': bool(active),
        'groupIds': set(group_ids) if group_ids else set(),
        'updatedAt': _now_iso(),
        'gsi1pk': f'SCIMID#{scim_id}',
        'gsi1sk': f'SCIMID#{scim_id}',
        'gsi2pk': f'USERNAME#{(user_name or "").lower()}',
        'gsi2sk': f'USERNAME#{(user_name or "").lower()}',
    }
    # DynamoDB rejects empty string sets; drop the attr when there are no groups.
    if not item['groupIds']:
        del item['groupIds']
    _table().put_item(Item=item)
    return item


def get_user_by_external_id(external_id):
    resp = _table().get_item(Key={'pk': user_pk(external_id), 'sk': user_pk(external_id)})
    return resp.get('Item')


def get_user_by_scim_id(scim_id):
    resp = _table().query(
        IndexName='GSI1',
        KeyConditionExpression=Key('gsi1pk').eq(f'SCIMID#{scim_id}'),
        Limit=1,
    )
    items = resp.get('Items', [])
    return items[0] if items else None


def get_user_by_user_name(user_name):
    resp = _table().query(
        IndexName='GSI2',
        KeyConditionExpression=Key('gsi2pk').eq(f'USERNAME#{(user_name or "").lower()}'),
        Limit=1,
    )
    items = resp.get('Items', [])
    return items[0] if items else None


def delete_user_by_scim_id(scim_id):
    item = get_user_by_scim_id(scim_id)
    if not item:
        return False
    _table().delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
    return True


def set_user_active_by_scim_id(scim_id, active):
    item = get_user_by_scim_id(scim_id)
    if not item:
        return None
    _table().update_item(
        Key={'pk': item['pk'], 'sk': item['sk']},
        UpdateExpression='SET active = :a, updatedAt = :u',
        ExpressionAttributeValues={':a': bool(active), ':u': _now_iso()},
    )
    item['active'] = bool(active)
    return item


# ---------------------------------------------------------------- groups

def put_group(group_id, display_name):
    item = {
        'pk': group_pk(group_id),
        'sk': group_pk(group_id),
        'groupId': group_id,
        'displayName': display_name or '',
        'updatedAt': _now_iso(),
    }
    _table().put_item(Item=item)
    return item


def get_group(group_id):
    resp = _table().get_item(Key={'pk': group_pk(group_id), 'sk': group_pk(group_id)})
    return resp.get('Item')


def set_group_display_name(group_id, display_name):
    _table().update_item(
        Key={'pk': group_pk(group_id), 'sk': group_pk(group_id)},
        UpdateExpression='SET displayName = :d, updatedAt = :u',
        ExpressionAttributeValues={':d': display_name or '', ':u': _now_iso()},
    )


def delete_group(group_id):
    item = get_group(group_id)
    if not item:
        return False
    _table().delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
    return True


# -------------------------------------------- membership fan-out (denormalised)

def add_member(group_id, user_scim_id):
    """Add group_id to the referenced user's denormalised groupIds set."""
    user = get_user_by_scim_id(user_scim_id)
    if not user:
        return False
    _table().update_item(
        Key={'pk': user['pk'], 'sk': user['sk']},
        UpdateExpression='ADD groupIds :g SET updatedAt = :u',
        ExpressionAttributeValues={':g': {group_id}, ':u': _now_iso()},
    )
    return True


def remove_member(group_id, user_scim_id):
    """Remove group_id from the referenced user's denormalised groupIds set."""
    user = get_user_by_scim_id(user_scim_id)
    if not user:
        return False
    _table().update_item(
        Key={'pk': user['pk'], 'sk': user['sk']},
        UpdateExpression='DELETE groupIds :g SET updatedAt = :u',
        ExpressionAttributeValues={':g': {group_id}, ':u': _now_iso()},
    )
    return True
