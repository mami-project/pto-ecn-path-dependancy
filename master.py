import datetime
import json

from ptocore.analyzercontext import AnalyzerContext
from ptocore.sensitivity import margin
from ptocore.collutils import grouper

print("--> Good morning! My name is pto-ecn-path-dependancy")

ac = AnalyzerContext()
OFFSET = datetime.timedelta(hours = 2)
max_action_id, timespans = margin(OFFSET, ac.action_set)

# only analyze one timespan per time
time_from, time_to = timespans[0]
ac.set_result_info(max_action_id, [(time_from, time_to)])

print("--> running with max action id: {}".format(max_action_id))
print("--> running with time from: {}".format(time_from))
print("--> running with time to: {}".format(time_to))

# The observations that we are interested in.
input_types = [
    'ecn.connectivity.works',
    'ecn.connectivity.broken',
    'ecn.connectivity.transient',
    'ecn.connectivity.offline'
]

minimum_of_sips = 5
print("--> running with minimum_of_sips: {}".format(minimum_of_sips))

stages = [
    # Get all valid inputs within the requested timespan
    {
        '$match': {
            # Question to self, are new observations pushed to the frot
            # or back of the array? Is it right to check the zeroth
            # element for validity? TODO
            'action_ids.0.valid': True,
            'conditions': {'$in': input_types},
            'time.from': {'$gte': time_from},
            'time.to': {'$lte': time_to}
        }
    },
    # Create a record for every individual observation
    {
        '$unwind': '$conditions'
    },
    # Only keep the observations in our input types
    {
        '$match': {
            'conditions': {'$in': input_types}
        }
    },
    # Group by destination ip
    {
        '$group': {
            '_id': {'$arrayElemAt': ['$path', -1]},
            'sips': {'$addToSet': {'$arrayElemAt': ['$path', 0]}},
            'conditions': {'$addToSet': '$conditions'},
            'obs': {'$push': '$_id'},
            'time_from': {'$min': '$time.from'},
            'time_to': {'$max': '$time.to'}
        }
    },
    # Count the number of source ips
    {
        '$project': {
            'conditions': 1,
            'num_sips': {'$size': '$sips'},
            'sips': 1,
            'obs': 1,
            'time_from': 1,
            'time_to': 1
        }
    },
    # Only analyse if we have results from at least three source ips
    {
        '$match': {
            'num_sips': {'$gte': minimum_of_sips}
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
                                                    'ecn.connectivity.broken']}
                    }
                }
            },
            'any_works': {'$anyElementTrue': {
                    '$map': {
                        'input': '$conditions',
                        'as': 'condition',
                        'in': {'$eq': ['$$condition',
                                                    'ecn.connectivity.works']}
                    }
                }
            },
            'any_transient': {'$anyElementTrue': {
                    '$map': {
                        'input': '$conditions',
                        'as': 'condition',
                        'in': {'$eq': ['$$condition',
                                                'ecn.connectivity.transient']}
                    }
                }
            },
            'any_offline': {'$anyElementTrue': {
                    '$map': {
                        'input': '$conditions',
                        'as': 'condition',
                        'in': {'$eq': ['$$condition',
                                                  'ecn.connectivity.offline']}
                    }
                }
            },
            'path': ['*', '$_id'],
            'value': {'sips': '$sips'},
            'sources.obs': '$obs',
            'time.from': '$time_from',
            'time.to': '$time_to'
        }
    },
    # If there are any br0ken paths, then we are interested
    # However, if there are transient or ofline paths, that means that we
    # probably can't trust the measurement, so we dont process it.
    {
        '$match': {
            'any_broken': True,
            'any_transient': False,
            'any_offline': False
        }
    },
    # If there are also some working paths, then we have path dependency
    # If there are no working paths, then we have host dependency
    {
        '$project': {
            'conditions': {'$cond':
                {
                    'if': '$any_works',
                    'then': ['ecn.path_dependent'],
                    'else': ['ecn.site_dependent']
                }
            },
            'path': 1,
            'value': 1,
            'sources.obs': 1,
            'time.from': 1,
            'time.to': 1,
            '_id': 0
        }
    }
]
print("--> starting aggregation")
cursor = ac.observations_coll.aggregate(stages, allowDiskUse=True)
print("--> starting insertion in to DB")
for observations in grouper(cursor, 1000):
    ac.temporary_coll.insert_many(list(observations))

print("--> Goodnight!")
