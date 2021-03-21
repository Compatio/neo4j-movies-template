import binascii
import hashlib
import os
import ast
import re
import sys
import uuid
import json
from dotenv import load_dotenv, find_dotenv
from datetime import datetime
from functools import wraps

from flask import Flask, g, request, send_from_directory, abort, request_started
from flask_cors import CORS
from flask_restful import Resource, reqparse
from flask_restful_swagger_2 import Api, swagger, Schema
from flask_json import FlaskJSON, json_response

from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import Neo4jError
import neo4j.time

load_dotenv(find_dotenv())

app = Flask(__name__)

CORS(app)
FlaskJSON(app)

api = Api(app, title='Flask GMS Test', api_version='0.0.1')


@api.representation('application/json')
def output_json(data, code, headers=None):
    return json_response(data_=data, headers_=headers, status_=code)


def env(key, default=None, required=True):
    """
    Retrieves environment variables and returns Python natives. The (optional)
    default will be returned if the environment variable does not exist.
    """
    try:
        value = os.environ[key]
        return ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value
    except KeyError:
        if default or not required:
            return default
        raise RuntimeError("Missing required environment variable '%s'" % key)


# orig
# DATABASE_USERNAME = env('MOVIE_DATABASE_USERNAME')
# DATABASE_PASSWORD = env('MOVIE_DATABASE_PASSWORD')
# DATABASE_URL = env('MOVIE_DATABASE_URL')

# gms
DATABASE_USERNAME = env('PROD_MASTER_USERNAME')
DATABASE_PASSWORD = env('PROD_MASTER_PASSWORD')
DATABASE_URL = env('PROD_MASTER_URL')
# GAIA_KEY = env('XRS_API_KEY')

# # gms
# DATABASE_USERNAME = env('DEV_GRAPH_USERNAME')
# DATABASE_PASSWORD = env('DEV_GRAPH_PASSWORD')
# DATABASE_URL = env('DEV_GRAPH_URL')

driver = GraphDatabase.driver(DATABASE_URL, auth=basic_auth(DATABASE_USERNAME, str(DATABASE_PASSWORD)))

app.config['SECRET_KEY'] = env('SECRET_KEY')


def get_db():
    if not hasattr(g, 'neo4j_db'):
        g.neo4j_db = driver.session()
    return g.neo4j_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'neo4j_db'):
        g.neo4j_db.close()


def set_user(sender, **extra):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        g.user = {'id': None}
        return
    match = re.match(r'^Token (\S+)', auth_header)
    if not match:
        abort(401, 'invalid authorization format. Follow `Token <token>`')
        return
    token = match.group(1)

    def get_user_by_token(tx, token):
        return tx.run(
            '''
            MATCH (user:User {api_key: $api_key}) RETURN user
            ''', {'api_key': token}
        ).single()

    db = get_db()
    result = db.read_transaction(get_user_by_token, token)
    try:
        g.user = result['user']
    except (KeyError, TypeError):
        abort(401, 'invalid authorization key')
    return


request_started.connect(set_user, app)


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'message': 'no authorization provided'}, 401
        return f(*args, **kwargs)

    return wrapped


class GenreModel(Schema):
    type = 'object'
    properties = {
        'id': {
            'type': 'integer',
        },
        'name': {
            'type': 'string',
        }
    }


class MovieModel(Schema):
    type = 'object'
    properties = {
        'id': {
            'type': 'string',
        },
        'title': {
            'type': 'string',
        },
        'summary': {
            'type': 'string',
        },
        'released': {
            'type': 'string',
        },
        'duration': {
            'type': 'integer',
        },
        'rated': {
            'type': 'string',
        },
        'tagline': {
            'type': 'string',
        },
        'poster_image': {
            'type': 'string',
        },
        'my_rating': {
            'type': 'integer',
        }
    }


class PersonModel(Schema):
    type = 'object'
    properties = {
        'id': {
            'type': 'integer',
        },
        'name': {
            'type': 'string',
        },
        'poster_image': {
            'type': 'string',
        }
    }


class UserModel(Schema):
    type = 'object'
    properties = {
        'id': {
            'type': 'string',
        },
        'username': {
            'type': 'string',
        },
        'avatar': {
            'type': 'object',
        }
    }


class IndustryModel(Schema):
    type = 'object'
    properties = {
        'active': {
            'type': 'string'
        },
        'created_at': {
            'type': 'string'
        },
        'description': {
            'type': 'string'
        },
        'gmsid': {
            'type': 'string'
        },
        'name': {
            'type': 'string'
        },
        'note': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        },

    }


class CategoryModel(Schema):
    type = 'object'
    properties = {
        'active': {
            'type': 'string'
        },
        'created_at': {
            'type': 'string'
        },
        'description': {
            'type': 'string'
        },
        'gmsid': {
            'type': 'string'
        },
        'image_url': {
            'type': 'string'
        },
        'name': {
            'type': 'string'
        },
        'note': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        }

    }


class AttributeModel(Schema):
    type = 'object'
    properties = {
        'abs_enabled': {
            'type': 'string'
        },
        'abs_properties': {
            'type': 'string'
        },
        'active': {
            'type': 'string'
        },
        'allowed_chars': {
            'type': 'string'
        },
        'allowed_user_defined_values': {
            'type': 'string'
        },
        'attr_inheritance': {
            'type': 'string'
        },
        'child_attr': {
            'type': 'string'
        },
        'created_at': {
            'type': 'string'
        },
        'datatype': {
            'type': 'string'
        },
        'description': {
            'type': 'string'
        },
        'extra_criteria_value1': {
            'type': 'string'
        },
        'extra_criteria_value2': {
            'type': 'string'
        },
        'gmsid': {
            'type': 'string'
        },
        'multiselect': {
            'type': 'string'
        },
        'multiselect_output_range': {
            'type': 'string'
        },
        'name': {
            'type': 'string'
        },
        'note': {
            'type': 'string'
        },
        'prohibited_chars': {
            'type': 'string'
        },
        'show_on_navbar': {
            'type': 'string'
        },
        'special_formatting': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        },
        'validation': {
            'type': 'string'
        },
        'validation_error_alert': {
            'type': 'string'
        },
        'validation_error_alert_body': {
            'type': 'string'
        },
        'validation_error_alert_style': {
            'type': 'string'
        },
        'validation_error_alert_title': {
            'type': 'string'
        },
        'validation_input_message': {
            'type': 'string'
        },
        'validation_input_message_body': {
            'type': 'string'
        },
        'validation_input_message_title': {
            'type': 'string'
        },
        'validation_range': {
            'type': 'string'
        },
        'validation_type': {
            'type': 'string'
        },
        'validation_type_extra_criteria': {
            'type': 'string'
        }

    }


class AttributeValueModel(Schema):
    type = 'object'
    properties = {
        'active': {
            'type': 'string'
        },
        'created_at': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        },
        'value': {
            'type': 'string'
        }
    }


class ProductModel(Schema):
    type = 'object'
    properties = {
        'active': {
            'type': 'string'
        },
        'created_at': {
            'type': 'string'
        },
        'description': {
            'type': 'string'
        },
        'min_ad_price': {
            'type': 'string'
        },
        'model_number': {
            'type': 'string'
        },
        'name': {
            'type': 'string'
        },
        'normalized_min_ad_price': {
            'type': 'string'
        },
        'publication': {
            'type': 'string'
        },
        'test_set': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        },
        'version': {
            'type': 'string'
        }
    }


class AnalyticsEventModel(Schema):
    type = 'object'
    properties = {
        'application': {
            'type': 'string'
        },
        'domain_url': {
            'type': 'string'
        },
        'event_type': {
            'type': 'string'
        },
        'platform': {
            'type': 'string'
        },
        'raw_payload': {
            'type': 'string'
        },
        'session_id': {
            'type': 'string'
        },
        'timestamp': {
            'type': 'string'
        }
    }


class ScoredProductModel(Schema):
    type = 'object'
    properties = {
        'product': {
            'type': 'string'
        },
        'score': {
            'type': 'double'
        },
        'variant_id': {
            'type': 'string'
        },
        'parent_product_id': {
            'type': 'string'
        }
    }


class CategoryScoredProductsModel(Schema):
    type = 'object'
    properties = {
        'category': {
            'type': CategoryModel
        },
        'products': {
            'type': 'array',
            'items': ScoredProductModel
        }
    }


class SmartBuilderModel(Schema):
    type = 'object'
    properties = {
        'input': {
            'type': 'object'
        },
        'results': {
            'type': 'array',
            'items': CategoryScoredProductsModel
        }
    }


def serialize_scored_product(scored):
    return {
        'product': scored['product'],
        'score': scored['score'],
        'variant_id': scored['variant_id'],
        'parent_product_id': scored['parent_product_id']
    }


def serialize_scored_category(category):
    return {
        'category': category['cat'],
        'products': [serialize_scored_product(p) for p in category['products']]
    }


def serialize_smart_builder(context, results, validation):
    ans = {}
    for record in results:
        ans[record['category']] = record['prods']
    return {
        'input': dict(context),
        'results': dict(ans),
        'validation': dict(validation)
    }


def serialize_industry(industry):
    return {
        'active': industry['active'],
        'created_at': industry['created_at'],
        'description': industry['description'],
        'gmsid': industry['gmsid'],
        'name': industry['name'],
        'note': industry['note'],
        'uid': industry['uid'],
        'updated_at': industry['updated_at']
    }


def serialize_industry(industry):
    return {
        'active': industry['active'],
        'created_at': industry['created_at'],
        'description': industry['description'],
        'gmsid': industry['gmsid'],
        'name': industry['name'],
        'note': industry['note'],
        'uid': industry['uid'],
        'updated_at': industry['updated_at']
    }


def serialize_category(category):
    return {
        'active': category['active'],
        'created_at': category['created_at'],
        'description': category['description'],
        'gmsid': category['gmsid'],
        'image_url': category['image_url'],
        'name': category['name'],
        'note': category['note'],
        'uid': category['uid'],
        'updated_at': category['updated_at']
    }


def serialize_attribute(attribute):
    return {
        'abs_enabled': attribute['abs_enabled'],
        'abs_properties': attribute['abs_properties'],
        'active': attribute['active'],
        'allowed_chars': attribute['allowed_chars'],
        'allowed_user_defined_values': attribute['allowed_user_defined_values'],
        'attr_inheritance': attribute['attr_inheritance'],
        'child_attr': attribute['child_attr'],
        'created_at': attribute['created_at'],
        'datatype': attribute['datatype'],
        'description': attribute['description'],
        'extra_criteria_value1': attribute['extra_criteria_value1'],
        'extra_criteria_value2': attribute['extra_criteria_value2'],
        'gmsid': attribute['gmsid'],
        'multiselect': attribute['multiselect'],
        'multiselect_output_range': attribute['multiselect_output_range'],
        'name': attribute['name'],
        'note': attribute['note'],
        'prohibited_chars': attribute['prohibited_chars'],
        'show_on_navbar': attribute['show_on_navbar'],
        'special_formatting': attribute['special_formatting'],
        'uid': attribute['uid'],
        'updated_at': attribute['updated_at'],
        'validation': attribute['validation'],
        'validation_error_alert': attribute['validation_error_alert'],
        'validation_error_alert_body': attribute['validation_error_alert_body'],
        'validation_error_alert_style': attribute['validation_error_alert_style'],
        'validation_error_alert_title': attribute['validation_error_alert_title'],
        'validation_input_message': attribute['validation_input_message'],
        'validation_input_message_body': attribute['validation_input_message_body'],
        'validation_input_message_title': attribute['validation_input_message_title'],
        'validation_range': attribute['validation_range'],
        'validation_type': attribute['validation_type'],
        'validation_type_extra_criteria': attribute['validation_type_extra_criteria']
    }


def serialize_value(value):
    return {
        'active': value['active'],
        'created_at': value['created_at'],
        'uid': value['uid'],
        'updated_at': value['updated_at'],
        'value': value['value']
    }


def serialize_product(product):
    return {
        'active': product['active'],
        'created_at': product['created_at'],
        'description': product['description'],
        'min_ad_price': product['min_ad_price'],
        'model_number': product['model_number'],
        'name': product['name'],
        'normalized_min_ad_price': product['normalized_min_ad_price'],
        'publication': product['publication'],
        'test_set': product['test_set'],
        'uid': product['uid'],
        'updated_at': product['updated_at'],
        'version': product['version']
    }


def serialize_event(event, payload):
    return {
        'application': event['application'],
        'domain_url': event['domain_url'],
        'event_type': event['event_type'],
        'payload': payload,
        'platform': event['platform'],
        'raw_payload': event['raw_payload'],
        'session_id': event['session_id'],
        'timestamp': event['timestamp']
    }


def serialize_genre(genre):
    return {
        'id': genre['id'],
        'name': genre['name'],
    }


def serialize_movie(movie, my_rating=None):
    return {
        'id': movie['tmdbId'],
        'title': movie['title'],
        'summary': movie['plot'],
        'released': movie['released'],
        'duration': movie['runtime'],
        'rated': movie['imdbRating'],
        'tagline': movie['plot'],
        'poster_image': movie['poster'],
        'my_rating': my_rating,
    }


def serialize_person(person):
    return {
        'id': person['tmdbId'],
        'name': person['name'],
        'poster_image': person['poster'],
    }


def serialize_user(user):
    return {
        'id': user['id'],
        'username': user['username'],
        'avatar': {
            'full_size': 'https://www.gravatar.com/avatar/{}?d=retro'.format(hash_avatar(user['username']))
        }
    }


def hash_password(username, password):
    if sys.version[0] == 2:
        s = '{}:{}'.format(username, password)
    else:
        s = '{}:{}'.format(username, password).encode('utf-8')
    return hashlib.sha256(s).hexdigest()


def hash_avatar(username):
    if sys.version[0] == 2:
        s = username
    else:
        s = username.encode('utf-8')
    return hashlib.md5(s).hexdigest()


class ApiDocs(Resource):
    def get(self, path=None):
        if not path:
            path = 'index.html'
        return send_from_directory('swaggerui', path)


class CategoryListByIndustry(Resource):
    @swagger.doc({
        'tags': ['categories'],
        'summary': 'Find all categories for an industry',
        'description': 'Returns all categories for an industry',
        'parameters': [
            {
                'name': 'industry_uid',
                'description': 'industry id',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of categories for an industry',
                'schema': CategoryModel,
            }
        }
    })
    def get(self):
        def get_categories_by_industry(tx):
            return list(tx.run('MATCH (category:Category)--(i:Industry {uid:$industry_uid}) RETURN category',
                               {'industry_uid': industry_uid}))

        db = get_db()
        # print(request.args.get('industry_uid'))
        industry_uid = request.args.get('industry_uid')
        result = db.write_transaction(get_categories_by_industry, industry_uid)
        return [serialize_category(record['category']) for record in result]


# Not sure this is useful anymore; was to me ! :D
class AnalyticsEventByDateRange(Resource):
    @swagger.doc({
        'tags': ['events'],
        'summary': 'Find analytics events by timestamp range',
        'description': 'Returns a list of analytics events which occurred between a range of timestamp inputs',
        'parameters': [
            {
                'name': 'start',
                'description': 'start timestamp',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
            {
                'name': 'end',
                'description': 'end timestamp',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of analytics events occurring between the specified timestamps',
                'schema': {
                    'type': 'array',
                    'items': AnalyticsEventModel,
                }
            }
        }
    })
    def get(self):
        try:
            params = {'start': request.args.get('start'), 'end': request.args.get('end')}
        except ValueError:
            return {'description': 'invalid year format'}, 400

        def get_event_list_by_date_range(tx, params):
            return list(tx.run(
                '''
                MATCH (e:Event)
                WHERE $start <= e.timestamp <= $end
                WITH e
                OPTIONAL MATCH (e)-[x]-(s:Sku)
                WITH e, collect(properties(x)) as payload
                ORDER BY e.timestamp
                RETURN payload, properties(e) as event
                ''', params
            ))

        # print(request.headers)
        db = get_db()
        result = db.read_transaction(get_event_list_by_date_range, params)
        return [serialize_event(record['event'], record['payload']) for record in result]


# catalog mapping
class SkuMappingForProductList(Resource):
    @swagger.doc({
        'tags': ['products'],
        'summary': 'Find product skus by merchant_key',
        'description': 'Returns a list of analytics events which occurred between a range of timestamp inputs',
        'parameters': [
            {
                'name': 'variant_id',
                'description': 'start timestamp',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
            {
                'name': 'end',
                'description': 'end timestamp',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of analytics events occurring between the specified timestamps',
                'schema': {
                    'type': 'array',
                    'items': AnalyticsEventModel,
                }
            }
        }
    })
    def get(self, start, end):
        try:
            params = {'start': start, 'end': end}
        except ValueError:
            return {'description': 'invalid year format'}, 400

        def get_event_list_by_date_range(tx, params):
            return list(tx.run(
                '''
                MATCH (e:Event)
                WHERE $start <= e.timestamp <= $end
                WITH e
                OPTIONAL MATCH (e)-[x]-(s:Sku)
                WITH e, collect(properties(x)) as payload
                ORDER BY e.timestamp
                RETURN payload, properties(e) as event
                ''', params
            ))

        db = get_db()
        result = db.read_transaction(get_event_list_by_date_range, params)
        return [serialize_event(record['event'], record['payload']) for record in result]


class DynamicConfigurator(Resource):
    @swagger.doc({
        'tags': ['SmartBuilder'],
        'summary': 'Find SmartBuilder results for provided input',
        'description': 'Returns scored compatible products by category for provided input',
        'parameters': [
            {
                'name': 'product_selections',
                'description': 'currently selected products, as JSON string',
                'in': 'path',
                'type': 'string',
                'required': False
            }, {
                'name': 'model_id',
                'description': 'uid for configurator, "" for none',
                'in': 'path',
                'type': 'string',
                'required': False
            }, {
                'name': 'merchant_key',
                'description': 'key for merchant',
                'in': 'path',
                'type': 'string',
                'required': False
            }, {
                'name': 'variant_id',
                'description': 'list of variant ids',
                'in': 'path',
                'type': 'array',
                'items': {
                    'type': 'string'
                },
                'required': False
            },
        ],
        'responses': {
            '200': {
                'description': 'SmartBuilder input and results, includes product attributes if no merchant_key',
                'schema': SmartBuilderModel,
            },
            '401': {
                'description': 'invalid / missing authentication',
            },
        }
    })
    def get(self):
        context = {
            'product_selections': request.args.get('product_selections'),
            'model_id': request.args.get('model_id'),
            'merchant_key': request.args.get('merchant_key'),
            'variant_id': request.args.get('variant_id')
        }
        if context['variant_id'] is not None:
            context['variant_id'] = context['variant_id'].split(',')

        def smart_builder(tx, context):
            # if product selections isn't empty
            if context['product_selections'] is not None:
                context['product_selections'] = json.loads(context['product_selections'])
            elif context['merchant_key'] is not None and context['variant_id'] is not None:
                # empty dict
                context['product_selections'] = {}
                # for each categorized product
                for record in catalog_map_input(tx, context):
                    # print(record)
                    # set up product selections dict
                    context['product_selections'][record['category']] = record['product']
            # if catalog mapping
            # if len(context['product_selections'].keys()) == 0 and context['merchant_key'] != '""' and context['variant_id'] != ['""']:
            #     zzz = catalog_map_input(tx, context)
            print(context)
            #     for record in zzz:
            #         context['product_selections'][record['category']] = record['product']
            # context['product_selections'] = dict(zzz)
            # if no model id
            if context['model_id'] is None:
                # run dynamic compatio
                return [serialize_smart_builder(context,
                                                score_products(tx, dynamic_compatio_products(tx, context), context),
                                                validate_build(tx, context))]
            else:
                # run configtr compatio
                return [serialize_smart_builder(context,
                                                score_products(tx, configtr_compatio_products(tx, context), context),
                                                validate_build(tx, context))]

        def catalog_map_input(tx, context):
            result = list(tx.run(
                '''
                UNWIND $variant_id AS variant
                MATCH (y:Party {key:$merchant_key})--(s:Sku{sku:variant})--(p:Product)--(c:Category)
                RETURN DISTINCT c.name as category, p.uid as product
                ''', {'variant_id': context['variant_id'], 'merchant_key': context['merchant_key']}
            ))
            return [{'category': record['category'], 'product': record['product']} for record in result]

        def score_products(tx, ans, context):
            qdata = {
                'data': [
                    {'cat': cat,
                     'prods': ans[cat],
                     'context': [context['product_selections'][k]
                                 for k in context['product_selections'].keys()]
                     } for cat in ans.keys()]
            }
            if context.get('merchant_key') is None:
                results = list(tx.run(
                    '''
                    UNWIND $data as cat
                    WITH cat
                    UNWIND cat.context as con
                    MATCH (q:Product{uid:con})
                    WITH cat,q
                    UNWIND cat.prods as prod
                    MATCH (q)-[c:COMPATIO]->(p:Product {uid:prod})
                    WITH DISTINCT cat,q,c,p
                    OPTIONAL MATCH (p)--(v:AttributeValue)-[va]-(a:Attribute{abs_enabled:True})
                    WHERE va.abs_show=True
                    WITH DISTINCT cat,p,c,q, {attr:a.name, values:collect(v.value)} as attr
                    WITH cat, {product:p.uid,score:avg(c.score),attrs:collect(distinct attr),edges:collect(distinct{rule:c.rule,score:c.score})} as prds
                    ORDER BY 1-prds.score
                    RETURN cat.cat as category, collect(prds)[..3200] as prods
                    ''', qdata
                ))
            else:
                qdata['merchant_key'] = context.get('merchant_key')
                results = list(tx.run(
                    '''
                    UNWIND $data as cat
                    WITH cat
                    UNWIND cat.context as con
                    MATCH (q:Product{uid:con})
                    WITH cat,q
                    UNWIND cat.prods as prod
                    MATCH (q)-[c:COMPATIO]->(p:Product {uid:prod})--(s:Sku)--(y:Party{key:$merchant_key})
                    WITH DISTINCT cat,p,c,q,s
                    WITH cat, {product:p.uid,variant_id:s.sku,parent_product_id:s.commerce_product_id,score:avg(c.score),edges:collect({rule:c.rule,score:c.score})} as prds
                    ORDER BY 1-prds.score
                    RETURN cat.cat as category, collect(prds)[..3200] as prods
                    ''', qdata
                ))
            return [{'category': record['category'], 'prods': record['prods']} for record in results]

        def dynamic_compatio_products(tx, context):
            result = list(tx.run(
                '''
                UNWIND $data as uid
                MATCH (root:Product {uid:uid})--(rc:Category)--(rule:CompatioRule)--(qc:Category)
                WITH DISTINCT root,rc,qc,collect(rule.uid) as rules
                OPTIONAL MATCH (root)-[e:COMPATIO]->(q:Product)--(qc)
                WHERE e.rule in rules
                WITH root,{cat_name:qc.name,products:collect(distinct q.uid)} as cat
                RETURN root.uid as root,collect(cat) as data
                ''', {
                    'data': [context['product_selections'][k]
                             for k in context['product_selections'].keys()
                             ]
                }
            ))
            # empty dict to fill
            ans = {}
            # for each product in context
            for query_cats in result:
                # for each category
                for c in query_cats['data']:
                    # print(len(c['products']))
                    # if not in the context already
                    if not c['cat_name'] in context['product_selections'].keys():
                        # if ans has category
                        if c['cat_name'] in ans.keys():
                            # intersect the products already available in ans with the new products
                            ans[c['cat_name']] = intersect_nodes([ans[c['cat_name']], c['products']])
                        # else
                        else:
                            # add category to ans
                            ans[c['cat_name']] = c['products']
            return dict(ans)

        def configtr_compatio_products(tx, context):
            result = list(tx.run(
                '''
                MATCH (configtr:Configurator{uid:$model_id})
                WITH configtr
                UNWIND $data as uid
                MATCH (root:Product {uid:uid})--(rc:Category)--(configtr)
                WITH DISTINCT configtr, root, rc
                MATCH (rc)--(rule:CompatioRule)--(qc:Category)--(configtr)
                WITH DISTINCT root,rc,qc,collect(rule.uid) as rules
                OPTIONAL MATCH (root)-[e:COMPATIO]-(q:Product)--(qc)
                WHERE e.rule in rules
                WITH root,{cat_name:qc.name,products:collect(distinct q.uid)} as cat
                RETURN root.uid as root,collect(cat) as data
                ''', {
                    'model_id': context['model_id'],
                    'data': [context['product_selections'][k]
                             for k in context['product_selections'].keys()
                             ]
                }
            ))
            # empty dict to fill
            ans = {}
            # for each product in context
            for query_cats in result:
                # for each category
                for c in query_cats['data']:
                    # if not in the context already
                    if not c['cat_name'] in context['product_selections'].keys():
                        # if ans has category
                        if c['cat_name'] in ans.keys():
                            # intersect the products already available in ans with the new products
                            ans[c['cat_name']] = intersect_nodes([ans[c['cat_name']], c['products']])
                        # else
                        else:
                            # add category to ans
                            ans[c['cat_name']] = c['products']
            return dict(ans)

        def validate_build(tx, context):
            result = list(tx.run(
                '''
                UNWIND $prods as prod
                MATCH (p:Product {uid:prod})--(c:Category)
                WITH DISTINCT p,c
                MATCH (c)--(r:CompatioRule{commit:True})--(d:Category)--(q:Product)
                WHERE q.uid in $prods
                WITH DISTINCT p,c,d,{rule_name:r.name,rule_uid:r.uid} as rule_by_cat
                WITH p,c, {context_cat:c.name,compatio_cat:d.name,rules:collect(DISTINCT rule_by_cat)} as rules_by_cat
                OPTIONAL MATCH (p)-[e:COMPATIO]-(q:Product)
                WHERE q.uid in $prods
                RETURN collect(distinct c.name) as cats,
                     collect(distinct e.rule) as compatio_edges, 
                     collect(distinct p.uid) as prods,
                     collect(distinct rules_by_cat) as rules
                ''', {'prods': [context['product_selections'][k]
                                for k in context['product_selections'].keys()]}
            ))
            print(result)
            data = {
                'cats': [record['cats'] for record in result][0],
                'prods': [record['prods'] for record in result][0],
                'rules': [record['rules'] for record in result][0],
                'compatio_edges': [record['compatio_edges'] for record in result][0]
            }
            print(data)
            ans = {}
            for pair in data['rules']:
                if not tuple(sorted((pair['context_cat'], pair['compatio_cat']))) in ans.keys():
                    ans[tuple(sorted((pair['context_cat'], pair['compatio_cat'])))] = pair['rules']
                else:
                    if not (ans[tuple(sorted((pair['context_cat'], pair['compatio_cat'])))] == pair['rules']):
                        print('ERROR!?! What did you even do???')
            next = {}
            # for each tuple
            for k in ans.keys():
                # make a string version of it
                next[str(k)] = ans[k]

            data['rules'] = next
            # computes boolean if the intersection of the edge list and the category pair's rule list has a length > 0 for all category pairs
            # one line to do all the loops below
            # data['result'] = all([len(utils.intersect_nodes([[j['rule_uid'] for j in data['data']['rules'][k]],data['data']['compatio_edges']]))>0 for k in data['data']['rules'].keys()])
            data['result'] = True
            data['failures'] = {}
            # for each category pair k
            for k in data['rules'].keys():
                # if the intersection of the rule uids for that category pair and the available edges is not >0
                if not len(intersect_nodes([[j['rule_uid'] for j in data['rules'][k]],
                                            data['compatio_edges']])) > 0:
                    # set result to False
                    data['result'] = False
                    # add category tuple data to failures
                    data['failures'][k] = data['rules'][k]

            # if result is still true
            if data['result']:
                del data['failures']
            return data

        db = get_db()

        result = db.write_transaction(smart_builder, context)
        # return result
        return [record for record in result]


class CompatioScoreByProduct(Resource):
    @swagger.doc({
        'tags': ['compatio'],
        'summary': 'Find all compatio products for an input product and calculate score',
        'description': 'Returns all compatio scored products for input product',
        'parameters': [
            {
                'name': 'root_uid',
                'description': 'input product uid',
                'in': 'path',
                'type': 'string',
                'required': False
            },
            {
                'name': 'variant_id',
                'description': 'input product variant id',
                'in': 'path',
                'type': 'string',
                'required': False
            },
            {
                'name': 'merchant_key',
                'description': 'merchant_key for catalog mapping',
                'in': 'path',
                'type': 'string',
                'required': False
            },
            {
                'name': 'live_score',
                'description': 'true for live calculation (uid only), false for xrs',
                'in': 'path',
                'type': 'boolean',
                'required': 'true'
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of genres',
                'schema': ScoredProductModel,
            }
        }
    })
    def get(self):
        root_uid = request.args.get('root_uid')
        live_score = request.args.get('live_score')
        merchant_key = request.args.get('merchant_key')
        variant_id = request.args.get('variant_id')

        def catalog_map_input(tx, variant_id, merchant_key):
            result = list(tx.run(
                '''
                MATCH (y:Party {key:$merchant_key})--(s:Sku{sku:$variant_id})--(p:Product)
                RETURN DISTINCT p.uid as product
                ''', {'variant_id': variant_id, 'merchant_key': merchant_key}
            ))
            return [record['product'] for record in result]


        def compatio_score(tx, root_uid):
            return list(tx.run(
                '''
                MATCH (root:Product{uid:$root_uid})-[scr:COMPATIO]->(prod:Product)--(c:Category)
                WITH root,prod,scr,c
                MATCH (prod)--(w:AttributeValue)-[s:SCORE]-(v:AttributeValue)--(root)
                WITH root,prod,s,c
                WITH root,c,prod,
                    abs(root.normalized_min_ad_price-prod.normalized_min_ad_price) as price_diff,
                    avg(s.weight) as scr_mean
                WITH root,c,{prod_uid:prod.uid,
                    compatioScore:1.0-(price_diff*$price_wt)-(scr_mean*$score_wt)} as compatio
                ORDER BY 1-compatio.compatioScore
                WITH root, {category:properties(c),products:collect(compatio)} as cat
                RETURN $score_wt as score_weight,$price_wt as price_weight,collect(cat) as categories
                ''', {'root_uid': root_uid, 'price_wt': 0.01, 'score_wt': (0.1618 * 2)}
            ))

        def xrs_native(tx, root_uid):
            return list(tx.run(
                '''
                MATCH (b:Category)--(p:Product {uid:$root_uid})-[scr:COMPATIO]-(prod:Product)--(c:Category)<-[r:RELEVANT_CATEGORY]-(b)
                WHERE scr.active = True
                WITH DISTINCT c,r,{merchantProductId:prod.uid, compatioScore:scr.score} as prods
                ORDER BY 1-prods.compatioScore
                WITH DISTINCT {categoryName:c.name, categoryID:c.uid, categoryImageUrl:c.image_url, relevanceRank:r.rank, products:collect(prods)} as compat 
                ORDER BY compat.relevanceRank
                RETURN collect(compat) as compatibleCategories
                ''', {'root_uid': root_uid}
                #     [..$products_per_category],  [..$maximum_categories]
            ))

        def xrs_mapped(tx, variant_id, merchant_key):
            return list(tx.run(
                '''
                MATCH (p:Party {key:$merchant_key})--(s:Sku {sku:$variant_id})--(root:Product)
                WITH p,s,root
                MATCH (root)-[scr:COMPATIO]->(prod:Product)--(c:Category)<-[r:RELEVANT_CATEGORY]-(b:Category)--(root)
                WHERE scr.score > 0 and scr.active = True
                WITH DISTINCT root,scr,prod,c,r,b,p
                MATCH (prod)--(cs:Sku)--(p)
                WITH DISTINCT root,c,r,{variant_id:cs.sku, parent_id:cs.commerce_product_id, compatioScore:scr.score} as prods
                ORDER BY 1-prods.compatioScore
                WITH DISTINCT root,{category:properties(c), relevance_rank:r.rank, products:collect(prods)} as compat 
                ORDER BY compat.relevanceRank
                RETURN root.uid as root_uid, collect(compat) as compatibleCategories
                ''', {'merchant_key': merchant_key, 'variant_id': variant_id}
                #     [..$products_per_category],  [..$maximum_categories]
            ))

        print(request.args)
        db = get_db()
        if live_score == 'True' or live_score == 'true' or live_score is True:
            if root_uid is None and merchant_key is not None and variant_id is not None:
                root_uid = db.write_transaction(catalog_map_input, variant_id, merchant_key)[0]
                print(root_uid)
            result = db.write_transaction(compatio_score, root_uid)
        elif merchant_key is not None and variant_id is not None:
            result = db.write_transaction(xrs_mapped, variant_id, merchant_key)
        else:
            result = db.write_transaction(xrs_native, root_uid)
        return [dict(record) for record in result]


#####


class CommentListByUser(Resource):
    @swagger.doc({
        'tags': ['genres'],
        'summary': 'Find all genres',
        'description': 'Returns all genres',
        'responses': {
            '200': {
                'description': 'A list of genres',
                'schema': GenreModel,
            }
        }
    })
    def get(self, user_id):
        def get_genres(tx):
            return list(tx.run(
                '''
                MATCH (configtr:Configurator{uid:$model_id})
                WITH configtr
                UNWIND $data as uid
                MATCH (root:Product {uid:uid})--(rc:Category)--(configtr)
                WITH DISTINCT configtr, root, rc
                MATCH (rc)--(rule:CompatioRule)--(qc:Category)--(configtr)
                WITH DISTINCT root,rc,qc,collect(rule.uid) as rules
                OPTIONAL MATCH (root)-[e:COMPATIO]-(q:Product)--(qc)
                WHERE e.rule in rules
                WITH root,{cat_name:qc.name,products:collect(distinct q.uid)} as cat
                RETURN root.uid as root,collect(cat) as data
                ''', {}
            ))

        db = get_db()
        result = db.write_transaction(get_genres)
        return [serialize_genre(record['genre']) for record in result]


#####


###


####


class GenreList(Resource):
    @swagger.doc({
        'tags': ['genres'],
        'summary': 'Find all genres',
        'description': 'Returns all genres',
        'responses': {
            '200': {
                'description': 'A list of genres',
                'schema': GenreModel,
            }
        }
    })
    def get(self):
        def get_genres(tx):
            return list(tx.run('MATCH (genre:Genre) SET genre.id=id(genre) RETURN genre'))

        db = get_db()
        result = db.write_transaction(get_genres)
        return [serialize_genre(record['genre']) for record in result]


class Movie(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movie by ID',
        'description': 'Returns a movie',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'default': 'Token <token goes here>',
                'required': False
            },
            {
                'name': 'id',
                'description': 'movie tmdbId, a string',
                'in': 'path',
                'type': 'string',
                'required': True,
            }
        ],
        'responses': {
            '200': {
                'description': 'A movie',
                'schema': MovieModel,
            },
            '404': {
                'description': 'movie not found'
            },
        }
    })
    def get(self, id):
        def get_movie(tx, user_id, id):
            return list(tx.run(
                '''
                MATCH (movie:Movie {tmdbId: $id})
                OPTIONAL MATCH (movie)<-[my_rated:RATED]-(me:User {id: $user_id})
                OPTIONAL MATCH (movie)<-[r:ACTED_IN]-(a:Person)
                OPTIONAL MATCH (related:Movie)<--(a:Person) WHERE related <> movie
                OPTIONAL MATCH (movie)-[:IN_GENRE]->(genre:Genre)
                OPTIONAL MATCH (movie)<-[:DIRECTED]-(d:Person)
                OPTIONAL MATCH (movie)<-[:PRODUCED]-(p:Person)
                OPTIONAL MATCH (movie)<-[:WRITER_OF]-(w:Person)
                WITH DISTINCT movie,
                my_rated,
                genre, d, p, w, a, r, related, count(related) AS countRelated
                ORDER BY countRelated DESC
                RETURN DISTINCT movie,
                my_rated.rating AS my_rating,
                collect(DISTINCT d) AS directors,
                collect(DISTINCT p) AS producers,
                collect(DISTINCT w) AS writers,
                collect(DISTINCT{ name:a.name, id:a.tmdbId, poster_image:a.poster, role:r.role}) AS actors,
                collect(DISTINCT related) AS related,
                collect(DISTINCT genre) AS genres
                ''', {'user_id': user_id, 'id': id}
            ))

        db = get_db()

        result = db.read_transaction(get_movie, g.user['id'], id)
        for record in result:
            return {
                'id': record['movie']['tmdbId'],
                'title': record['movie']['title'],
                'summary': record['movie']['plot'],
                'released': record['movie']['released'],
                'duration': record['movie']['runtime'],
                'rated': record['movie']['rated'],
                'tagline': record['movie']['plot'],
                'poster_image': record['movie']['poster'],
                'my_rating': record['my_rating'],
                'genres': [serialize_genre(genre) for genre in record['genres']],
                'directors': [serialize_person(director) for director in record['directors']],
                'producers': [serialize_person(producer) for producer in record['producers']],
                'writers': [serialize_person(writer) for writer in record['writers']],
                'actors': [
                    {
                        'id': actor['id'],
                        'name': actor['name'],
                        'role': actor['role'],
                        'poster_image': actor['poster_image'],
                    } for actor in record['actors']
                ],
                'related': [serialize_movie(related) for related in record['related']],
            }
        return {'message': 'movie not found'}, 404


class MovieList(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find all movies',
        'description': 'Returns a list of movies',
        'responses': {
            '200': {
                'description': 'A list of movies',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self):
        def get_movies(tx):
            return list(tx.run(
                '''
                MATCH (movie:Movie) RETURN movie
                '''
            ))

        db = get_db()
        result = db.read_transaction(get_movies)
        return [serialize_movie(record['movie']) for record in result]


class MovieListByGenre(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movie by genre id',
        'description': 'Returns a list of movies by genre',
        'parameters': [
            {
                'name': 'genre_id',
                'description': 'The name of the genre.',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of movies with the specified genre',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self, genre_id):
        def get_movies_by_genre(tx, genre_id):
            return list(tx.run(
                '''
                MATCH (movie:Movie)-[:IN_GENRE]->(genre:Genre)
                WHERE toLower(genre.name) = toLower($genre_id)
                    // while transitioning to the sandbox data
                    OR id(genre) = toInteger($genre_id)
                RETURN movie
                ''', {'genre_id': genre_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_by_genre, genre_id)
        return [serialize_movie(record['movie']) for record in result]


# Not sure this is useful anymore
class MovieListByDateRange(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movie by year range',
        'description': 'Returns a list of movies released between a range of years',
        'parameters': [
            {
                'name': 'start',
                'description': 'start year',
                'in': 'path',
                'type': 'integer',
                'required': 'true'
            },
            {
                'name': 'end',
                'description': 'end year',
                'in': 'path',
                'type': 'integer',
                'required': 'true'
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of movies released between the specified years',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self, start, end):
        try:
            params = {'start': start, 'end': end}
        except ValueError:
            return {'description': 'invalid year format'}, 400

        def get_movies_list_by_date_range(tx, params):
            return list(tx.run(
                '''
                MATCH (movie:Movie)
                WHERE movie.year > $start AND movie.year < $end
                RETURN movie
                ''', params
            ))

        db = get_db()
        result = db.read_transaction(get_movies_list_by_date_range, params)
        return [serialize_movie(record['movie']) for record in result]


class MovieListByPersonActedIn(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movies by actor',
        'description': 'Returns a list of movies that a person has acted in.',
        'parameters': [
            {
                'name': 'person_id',
                'description': 'person id',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of movies the specified person has acted in',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self, person_id):
        def get_movies_by_acted_in(tx, person_id):
            return list(tx.run(
                '''
                MATCH (actor:Actor {tmdbId: $person_id})-[:ACTED_IN]->(movie:Movie)
                RETURN DISTINCT movie
                ''', {'person_id': person_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_by_acted_in, person_id)
        return [serialize_movie(record['movie']) for record in result]


class MovieListByWrittenBy(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movies by writer',
        'description': 'Returns a list of movies writen by a person',
        'parameters': [
            {
                'name': 'person_id',
                'description': 'person id',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of movies the specified person has written',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self, person_id):
        def get_movies_list_written_by(tx, person_id):
            return list(tx.run(
                '''
                MATCH (actor:Writer {tmdbId: $person_id})-[:WRITER_OF]->(movie:Movie)
                RETURN DISTINCT movie
                ''', {'person_id': person_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_list_written_by, person_id)
        return [serialize_movie(record['movie']) for record in result]


class MovieListByDirectedBy(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Find movies by director',
        'description': 'Returns a list of movies directed by a person',
        'parameters': [
            {
                'name': 'person_id',
                'description': 'person id',
                'in': 'path',
                'type': 'string',
                'required': 'true'
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of movies the specified person has directed',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    def get(self, person_id):
        def get_movies_list_directed_by(tx, person_id):
            return list(tx.run(
                '''
                MATCH (actor:Director {tmdbId: $person_id})-[:DIRECTED]->(movie:Movie)
                RETURN DISTINCT movie
                ''', {'person_id': person_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_list_directed_by, person_id)
        return [serialize_movie(record['movie']) for record in result]


class MovieListRatedByMe(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'A list of movies the authorized user has rated.',
        'description': 'A list of movies the authorized user has rated.',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'default': 'Token <token goes here>',
                'required': True
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of movies the authorized user has rated',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    @login_required
    def get(self):
        def get_movies_rated_by_me(tx, user_id):
            return list(tx.run(
                '''
                MATCH (:User {id: $user_id})-[rated:RATED]->(movie:Movie)
                RETURN DISTINCT movie, rated.rating as my_rating
                ''', {'user_id': user_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_rated_by_me, g.user['id'])
        return [serialize_movie(record['movie'], record['my_rating']) for record in result]


class MovieListRecommended(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'A list of recommended movies for the authorized user.',
        'description': 'A list of recommended movies for the authorized user.',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'default': 'Token <token goes here>',
                'required': True
            },
        ],
        'responses': {
            '200': {
                'description': 'A list of recommended movies for the authorized user',
                'schema': {
                    'type': 'array',
                    'items': MovieModel,
                }
            }
        }
    })
    @login_required
    def get(self):
        def get_movies_list_recommended(tx, user_id):
            return list(tx.run(
                '''
                MATCH (me:User {id: $user_id})-[my:RATED]->(m:Movie)
                MATCH (other:User)-[their:RATED]->(m)
                WHERE me <> other
                AND abs(my.rating - their.rating) < 2
                WITH other,m
                MATCH (other)-[otherRating:RATED]->(movie:Movie)
                WHERE movie <> m 
                WITH avg(otherRating.rating) AS avgRating, movie
                RETURN movie
                ORDER BY avgRating desc
                LIMIT 25
                ''', {'user_id': user_id}
            ))

        db = get_db()
        result = db.read_transaction(get_movies_list_recommended, g.user['id'])
        return [serialize_movie(record['movie']) for record in result]


class Person(Resource):
    @swagger.doc({
        'tags': ['people'],
        'summary': 'Find person by id',
        'description': 'Returns a person',
        'parameters': [
            {
                'name': 'id',
                'description': 'person id',
                'in': 'path',
                'type': 'integer',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'A person',
                'schema': PersonModel,
            },
            '404': {
                'description': 'person not found'
            },
        }
    })
    def get(self, id):
        def get_person_by_id(tx, user_id):
            return list(tx.run(
                '''
                MATCH (person:Person {tmdbId: $id})
                OPTIONAL MATCH (person)-[:DIRECTED]->(d:Movie)
                OPTIONAL MATCH (person)<-[:PRODUCED]->(p:Movie)
                OPTIONAL MATCH (person)<-[:WRITER_OF]->(w:Movie)
                OPTIONAL MATCH (person)<-[r:ACTED_IN]->(a:Movie)
                OPTIONAL MATCH (person)-->(movies)<-[relatedRole:ACTED_IN]-(relatedPerson)
                RETURN DISTINCT person,
                collect(DISTINCT { name:d.title, id:d.tmdbId, poster_image:d.poster}) AS directed,
                collect(DISTINCT { name:p.title, id:p.tmdbId, poster_image:p.poster}) AS produced,
                collect(DISTINCT { name:w.title, id:w.tmdbId, poster_image:w.poster}) AS wrote,
                collect(DISTINCT{ name:a.title, id:a.tmdbId, poster_image:a.poster, role:r.role}) AS actedIn,
                collect(DISTINCT{ name:relatedPerson.name, id:relatedPerson.tmdbId, poster_image:relatedPerson.poster, role:relatedRole.role}) AS related
                ''', {'id': user_id}
            ))

        db = get_db()
        results = db.read_transaction(get_person_by_id, id)
        for record in results:
            return {
                'id': record['person']['id'],
                'name': record['person']['name'],
                'poster_image': record['person']['poster'],
                'directed': [
                    {
                        'id': movie['id'],
                        'name': movie['name'],
                        'poster_image': movie['poster_image'],
                    } for movie in record['directed']
                ],
                'produced': [
                    {
                        'id': movie['id'],
                        'name': movie['name'],
                        'poster_image': movie['poster_image'],
                    } for movie in record['produced']
                ],
                'wrote': [
                    {
                        'id': movie['id'],
                        'name': movie['name'],
                        'poster_image': movie['poster_image'],
                    } for movie in record['wrote']
                ],
                'actedIn': [
                    {
                        'id': movie['id'],
                        'name': movie['name'],
                        'poster_image': movie['poster_image'],
                        'role': movie['role'],
                    } for movie in record['actedIn']
                ],
                'related': [
                    {
                        'id': person['id'],
                        'name': person['name'],
                        'poster_image': person['poster_image'],
                        'role': person['role'],
                    } for person in record['related']
                ],
            }
        return {'message': 'person not found'}, 404


class PersonList(Resource):
    @swagger.doc({
        'tags': ['people'],
        'summary': 'Find all people',
        'description': 'Returns a list of people',
        'responses': {
            '200': {
                'description': 'A list of people',
                'schema': {
                    'type': 'array',
                    'items': PersonModel,
                }
            }
        }
    })
    def get(self):
        def get_persons_list(tx):
            return list(tx.run(
                '''
                MATCH (person:Person) RETURN person
                '''
            ))

        db = get_db()
        results = db.read_transaction(get_persons_list)
        return [serialize_person(record['person']) for record in results]


class PersonBacon(Resource):
    @swagger.doc({
        'tags': ['people'],
        'summary': 'Find all Bacon paths',
        'description': 'Returns all bacon paths from person 1 to person 2',
        'parameters': [
            {
                'name': 'name1',
                'description': 'Name of the origin user',
                'in': 'query',
                'type': 'string',
                'required': True,
            },
            {
                'name': 'name2',
                'description': 'Name of the target user',
                'in': 'query',
                'type': 'string',
                'required': True,
            }
        ],
        'responses': {
            '200': {
                'description': 'A list of people',
                'schema': {
                    'type': 'array',
                    'items': PersonModel,
                }
            }
        }
    })
    def get(self):
        name1 = request.args['name1']
        name2 = request.args['name2']

        def get_bacon(tx, name1, name2):
            return list(tx.run(
                '''
                MATCH p = shortestPath( (p1:Person {name: $name1})-[:ACTED_IN*]-(target:Person {name: $name2}) )
                WITH [n IN nodes(p) WHERE n:Person | n] as bacon
                UNWIND(bacon) AS person
                RETURN DISTINCT person
                ''', {'name1': name1, 'name2': name2}
            ))

        db = get_db()
        results = db.read_transaction(get_bacon, name1, name2)
        return [serialize_person(record['person']) for record in results]


class Register(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Register a new user',
        'description': 'Register a new user',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {
                            'type': 'string',
                        },
                        'password': {
                            'type': 'string',
                        }
                    }
                }
            },
        ],
        'responses': {
            '201': {
                'description': 'Your new user',
                'schema': UserModel,
            },
            '400': {
                'description': 'Error message(s)',
            },
        }
    })
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username:
            return {'username': 'This field is required.'}, 400
        if not password:
            return {'password': 'This field is required.'}, 400

        def get_user_by_username(tx, username):
            return tx.run(
                '''
                MATCH (user:User {username: $username}) RETURN user
                ''', {'username': username}
            ).single()

        db = get_db()
        result = db.read_transaction(get_user_by_username, username)
        if result and result.get('user'):
            return {'username': 'username already in use'}, 400

        def create_user(tx, username, password):
            return tx.run(
                '''
                CREATE (user:User {id: $id, username: $username, password: $password, api_key: $api_key}) RETURN user
                ''',
                {
                    'id': str(uuid.uuid4()),
                    'username': username,
                    'password': hash_password(username, password),
                    'api_key': binascii.hexlify(os.urandom(20)).decode()
                }
            ).single()

        results = db.write_transaction(create_user, username, password)
        user = results['user']
        return serialize_user(user), 201


class Login(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Login',
        'description': 'Login',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {
                            'type': 'string',
                        },
                        'password': {
                            'type': 'string',
                        }
                    }
                }
            },
        ],
        'responses': {
            '200': {
                'description': 'succesful login'
            },
            '400': {
                'description': 'invalid credentials'
            }
        }
    })
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username:
            return {'username': 'This field is required.'}, 400
        if not password:
            return {'password': 'This field is required.'}, 400

        def get_user_by_username(tx, username):
            return tx.run(
                '''
                MATCH (user:User {username: $username}) RETURN user
                ''', {'username': username}
            ).single()

        db = get_db()
        result = db.read_transaction(get_user_by_username, username)
        try:
            user = result['user']
        except KeyError:
            return {'username': 'username does not exist'}, 400

        expected_password = hash_password(user['username'], password)
        if user['password'] != expected_password:
            return {'password': 'wrong password'}, 400
        return {
            'token': user['api_key']
        }


class UserMe(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Get your user',
        'description': 'Get your user',
        'parameters': [{
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'default': 'Token <token goes here>',
        }],
        'responses': {
            '200': {
                'description': 'the user',
                'schema': UserModel,
            },
            '401': {
                'description': 'invalid / missing authentication',
            },
        }
    })
    @login_required
    def get(self):
        return serialize_user(g.user)


class RateMovie(Resource):
    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Rate a movie from',
        'description': 'Rate a movie from 0-5 inclusive',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'required': True,
                'default': 'Token <token goes here>',
            },
            {
                'name': 'id',
                'description': 'movie tmdbId',
                'in': 'path',
                'type': 'string',
            },
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'rating': {
                            'type': 'integer',
                        },
                    }
                }
            },
        ],
        'responses': {
            '200': {
                'description': 'movie rating saved'
            },
            '401': {
                'description': 'invalid / missing authentication'
            }
        }
    })
    @login_required
    def post(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('rating', choices=list(range(0, 6)), type=int, required=True,
                            help='A rating from 0 - 5 inclusive (integers)')
        args = parser.parse_args()
        rating = args['rating']

        def rate_movie(tx, user_id, movie_id, rating):
            return tx.run(
                '''
                MATCH (u:User {id: $user_id}),(m:Movie {tmdbId: $movie_id})
                MERGE (u)-[r:RATED]->(m)
                SET r.rating = $rating
                RETURN m
                ''', {'user_id': user_id, 'movie_id': movie_id, 'rating': rating}
            )

        db = get_db()
        results = db.write_transaction(rate_movie, g.user['id'], id, rating)
        return {}

    @swagger.doc({
        'tags': ['movies'],
        'summary': 'Delete your rating for a movie',
        'description': 'Delete your rating for a movie',
        'parameters': [
            {
                'name': 'Authorization',
                'in': 'header',
                'type': 'string',
                'required': True,
                'default': 'Token <token goes here>',
            },
            {
                'name': 'id',
                'description': 'movie tmdbId',
                'in': 'path',
                'type': 'string',
            },
        ],
        'responses': {
            '204': {
                'description': 'movie rating deleted'
            },
            '401': {
                'description': 'invalid / missing authentication'
            }
        }
    })
    @login_required
    def delete(self, id):
        def delete_rating(tx, user_id, movie_id):
            return tx.run(
                '''
                MATCH (u:User {id: $user_id})-[r:RATED]->(m:Movie {tmdbId: $movie_id}) DELETE r
                ''', {'movie_id': movie_id, 'user_id': user_id}
            )

        db = get_db()
        db.write_transaction(delete_rating, g.user['id'], id)
        return {}, 204


# return intersection of multiple lists
def intersect_nodes(lists):
    # alt: empty or single list
    if len(lists) == 0:
        # return itself
        return lists
    elif len(lists) == 1:
        return lists[0]
    # base: exactly 2 lists
    elif len(lists) == 2:
        # return list of elements in both lists
        return list(set(lists[0]).intersection(lists[1]))
    # recur: >2 lists
    else:
        # remove one from lists
        i = lists.pop()
        # return list of elements in this list and all others
        return list(set(i).intersection(intersect_nodes(lists)))


api.add_resource(ApiDocs, '/docs', '/docs/<path:path>')
api.add_resource(GenreList, '/api/v0/genres')
api.add_resource(Movie, '/api/v0/movies/<string:id>')
api.add_resource(RateMovie, '/api/v0/movies/<string:id>/rate')
api.add_resource(MovieList, '/api/v0/movies')
api.add_resource(MovieListByGenre, '/api/v0/movies/genre/<string:genre_id>/')
api.add_resource(MovieListByDateRange, '/api/v0/movies/daterange/<int:start>/<int:end>')
api.add_resource(MovieListByPersonActedIn, '/api/v0/movies/acted_in_by/<string:person_id>')
api.add_resource(MovieListByWrittenBy, '/api/v0/movies/written_by/<string:person_id>')
api.add_resource(MovieListByDirectedBy, '/api/v0/movies/directed_by/<string:person_id>')
api.add_resource(MovieListRatedByMe, '/api/v0/movies/rated')
api.add_resource(MovieListRecommended, '/api/v0/movies/recommended')
api.add_resource(Person, '/api/v0/people/<string:id>')
api.add_resource(PersonList, '/api/v0/people')
api.add_resource(PersonBacon, '/api/v0/people/bacon')
api.add_resource(Register, '/api/v0/register')
api.add_resource(Login, '/api/v0/login')
api.add_resource(UserMe, '/api/v0/users/me')
api.add_resource(CategoryListByIndustry, '/api/gaia/categories/')
api.add_resource(AnalyticsEventByDateRange, '/api/gaia/analytics/events_by_date_range/')
api.add_resource(DynamicConfigurator,'/api/gaia/xdc/')
api.add_resource(CompatioScoreByProduct,'/api/gaia/score/')
