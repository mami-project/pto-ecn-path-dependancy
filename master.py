import json
import datetime
import collections


from ptocore.analyzercontext import AnalyzerContext
from ptocore.sensitivity import margin
from ptocore.collutils import grouper

def generate_dependency_conditions(source_conditions):
    conditions = list()

    condition_count = collections.Counter(source_conditions)

    # Check for weak ECN path dependency
    if      condition_count['ecn.connectivity.super.broken'] >= 1 \
        and condition_count['ecn.connectivity.super.works'] >= 1:

            conditions.append('ecn.path_dependent.weak')

    # Check for strict ECN path dependency
    if      condition_count['ecn.connectivity.super.broken'] >= 1 \
        and condition_count['ecn.connectivity.super.works'] >= 1 \
        and condition_count['ecn.connectivity.super.offline'] == 0 \
        and condition_count['ecn.connectivity.super.transient'] == 0 \
        and condition_count['ecn.connectivity.super.weird'] == 0:

            conditions.append('ecn.path_dependent.strict')

    # Check for strong ECN path dependency
    if      condition_count['ecn.connectivity.super.broken'] >= 2 \
        and condition_count['ecn.connectivity.super.works'] >= 1 \
        and condition_count['ecn.connectivity.super.offline'] == 0 \
        and condition_count['ecn.connectivity.super.transient'] == 0 \
        and condition_count['ecn.connectivity.super.weird'] == 0:

            conditions.append('ecn.path_dependent.strong')

    # Check for weak ECN site dependency
    if      condition_count['ecn.connectivity.super.broken'] >= 1 \
        and condition_count['ecn.connectivity.super.works'] == 0:

            conditions.append('ecn.site_dependent.weak')

        # Check for strict and strong ECN site dependency
    if      condition_count['ecn.connectivity.super.broken'] >= 1 \
        and condition_count['ecn.connectivity.super.works'] == 0 \
        and condition_count['ecn.connectivity.super.offline'] == 0 \
        and condition_count['ecn.connectivity.super.transient'] == 0 \
        and condition_count['ecn.connectivity.super.weird'] == 0:

            conditions.append('ecn.site_dependent.strict')
            conditions.append('ecn.site_dependent.strong')

    return conditions

def process_pipeline_document(document):
    # The new observation
    observation = dict()

    observation['conditions'] = \
        generate_dependency_conditions(document['source_conditions'])

    condition_count = collections.Counter(document['source_conditions'])

    observation['path'] = document['path']
    observation['time'] = document['time']
    observation['sources'] = document['sources']

    value = dict()
    observation['value'] = value
    value['locations'] = document['locations']
    value['count'] = dict()
    value['count']['broken'] = \
        condition_count['ecn.connectivity.super.broken']
    value['count']['works'] = \
        condition_count['ecn.connectivity.super.works']
    value['count']['offline'] = \
        condition_count['ecn.connectivity.super.offline']
    value['count']['transient'] = \
        condition_count['ecn.connectivity.super.transient']
    value['count']['weird'] = \
        condition_count['ecn.connectivity.super.weird']
    value['source_conditions'] = document['source_conditions']

    return observation



print("--> Good morning! My name is pto-ecn-path-dependancy")

ac = AnalyzerContext()
OFFSET = datetime.timedelta(hours = 2)
max_action_id, timespans = margin(OFFSET, ac.action_set)

# only analyze one timespan per time
time_from, time_to = timespans[0]
ac.set_result_info(max_action_id, [(time_from, time_to)])

print("--> I received {} timespans, but I am only processing one.".format(
    len(timespans)))
print("--> running with max action id: {}".format(max_action_id))
print("--> running with time from: {}".format(time_from))
print("--> running with time to: {}".format(time_to))

# The observations that we are interested in.
input_types = [
    'ecn.connectivity.super.works',
    'ecn.connectivity.super.broken',
    'ecn.connectivity.super.transient',
    'ecn.connectivity.super.offline',
    'ecn.connectivity.super.weird'
]

min_num_of_measurements = 2
min_num_of_locations = 4
print("--> running with min_num_of_measurements: {}".format(
    min_num_of_measurements))
print("--> running with min_num_of_locations: {}".format(
    min_num_of_locations))

stages = [
    # Get all valid inputs within the requested timespan
    {
        '$match': {
            # Question to self, are new observations pushed to the frot
            # or back of the array? Is it right to check the zeroth
            # element for validity?
            'action_ids.0.valid': True,
            'conditions': {'$in': input_types},
            'time.from': {'$gte': time_from},
            'time.to': {'$lte': time_to},
        }
    },

    # Count the number of times we measured from each location
    {
        '$project':{
            '_id':1,
            'condition': {'$arrayElemAt': ['$conditions', 0] },
            'path':1,
            'time':1,
            'location': '$value.location',
            'num_sources': {'$size': '$sources.obs'}
        }
    },
    # Throw everything where we didn't measure at least twice from
    {
        '$match': {
            'num_sources': {'$gte': min_num_of_measurements}
        }
    },
    # Group by destination ip
    {
        '$group': {
            '_id': {'$arrayElemAt': ['$path', -1]},
            'conditions': {'$push': '$condition'},
            'locations': {'$push': '$location'},
            'obs': {'$push': '$_id'},
            'time_from': {'$min': '$time.from'},
            'time_to': {'$max': '$time.to'}
        }
    },
    # Count the number of locations
    {
        '$project': {
            'conditions': 1,
            'num_locations': {'$size': '$locations'},
            'locations': 1,
            'obs': 1,
            'time_from': 1,
            'time_to': 1
        }
    },
    # Only analyse if we have results from at least three locations
    {
        '$match': {
            'num_locations': {'$gte': min_num_of_locations}
        }
    },

    # check if there are any broken, working or transient paths
    {
        '$project': {
            'any_broken': {'$anyElementTrue': {
                    '$map': {
                        'input': '$conditions',
                        'as': 'condition',
                        'in': {'$eq': ['$$condition',
                                    'ecn.connectivity.super.broken']}
                    }
                }
            },

            'source_conditions': '$conditions',
            'path': ['*', '$_id'],
            'locations': 1,
            'sources.obs': '$obs',
            'time.from': '$time_from',
            'time.to': '$time_to'
        }
    },

    # If there are any br0ken paths, then we are interested
    {
        '$match': {
            'any_broken': True,
        }
    }
]

print("--> starting aggregation")
cursor = ac.observations_coll.aggregate(stages, allowDiskUse=True)
print("--> starting final processing and insertion in to DB")
for documents in grouper(cursor, 1000):
    new_observations = []
    for document in documents:
        new_observations.append(process_pipeline_document(document))
    ac.temporary_coll.insert_many(new_observations)

print("--> Goodnight!")
