'''
Transaction family class for blockbee.
'''

import traceback
import sys
import hashlib
import logging
import json
import base64

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey


LOGGER = logging.getLogger(__name__)

FAMILY_NAME = "blockbee"

def _hash(data):
    '''Compute the SHA-512 hash and return the result as hex characters.'''
    return hashlib.sha512(data).hexdigest()

# Prefix for blockbee is the first six hex digits of SHA-512(TF name).
sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]

class blockbeeTransactionHandler(TransactionHandler):
    '''                                                       
    Transaction Processor class for the blockbee transaction family.       
                                                              
    This with the validator using the accept/get/set functions.
    It implements functions to deposit, withdraw, and transfer money.
    '''

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [self._namespace_prefix]

    def apply(self, transaction, context):
        '''This implements the apply function for this transaction handler.
                                                              
           This function does most of the work for this class by processing
           a single transaction for the blockbee transaction family.   
        '''                                                   
        
        # Get the payload and extract blockbee-specific information.
        header = transaction.header
        payload_list = transaction.payload.decode().split(",")
        operation = payload_list[0]
        
        edgehost = header.signer_public_key

        LOGGER.info("Operation = "+ operation)

        # format of operation set flow for device
        # setflow UserA Password1 EdgeUIT
        if operation == "setflow":
            if len(payload_list) == 4:
                userhost = payload_list[1] # username or edge(init_database)
                LOGGER.info('userhost {}'.format(userhost))
                passhost = payload_list[2] # password
                LOGGER.info('userhost {}'.format(passhost))
            # def _setflow(self, context, username, password, edgehost)
            self._setflow(self, context, userhost, passhost, edgehost)
        elif operation == "add_device":
            if len(payload_list) == 4:
                userhost = payload_list[1] # username or edge(init_database)
                LOGGER.info('userhost {}'.format(userhost))
                passhost = payload_list[2] # password
                LOGGER.info('userhost {}'.format(passhost))
            # _add_device(self, context, username, password, edgehost)
            self._add_device(self, context, userhost, passhost, edgehost)
        elif operation == "init_edge":
            # _init_edge(self, context, edgehost)
            self._init_edge(self, context, edgehost)
        else:
            LOGGER.info("Unhandled action. " +
                "Operation should be setflow, add_device or init_edge")

    def _setflow(self, context, username, password, edgehost):
        '''This function will authenticate for smart device. Then call rest api of controller to set flow direct for device'''
        edge_address = self._get_object_address(edgehost)
        current_entry = context.get_state(edge_address)

        if current_entry == []:
            LOGGER.info('[!] Edge host invalid')
            raise InternalError("State Error")
        else:
            LOGGER.info('[+] Edge host valid at address {}'.format(edge_address))
            #database mapping with edge host have structure
            # database = {
            #     "alice" :   "55205894fa7fd2e8017492d113c2317f92824f"
            #     "bob"   :   "55205894fa7fd2e8017492d113c2317f92824f"
            # }
            # database save with str(dumpdata).encode('utf-8')
            # to decrypt after query, we can
            # jsondata = json.loads(querydata.decode('utf-8'))
            get_data_node = current_entry[0].data   # str data encode utf 8
            json_data = json.loads(get_data_node.decode('utf-8'))

            passhash = _hash(password.encode('utf-8'))
            if json_data[username] == passhash:
                #call_rest_api(username)
                LOGGER.info('[+] Authentication success. Sending ACL to controller')
            else:
                LOGGER.info('[-] Username or password incorrect')
                raise InternalError("State Error")

    def _add_device(self, context, username, password, edgehost):
        edge_address = self._get_object_address(edgehost)
        current_entry = context.get_state(edge_address)

        if current_entry == []:
            LOGGER.info('[!] Edge host invalid')
            raise InternalError("State Error")
        else:
            #database mapping with edge host have structure
            # database = {
            #     "alice" :   "55205894fa7fd2e8017492d113c2317f92824f"
            #     "bob"   :   "55205894fa7fd2e8017492d113c2317f92824f"
            # }
            # database save with str(dumpdata).encode('utf-8')
            # to decrypt after query, we can
            # jsondata = json.loads(querydata.decode('utf-8'))
            LOGGER.info('[+] Edge host valid at address {}'.format(edge_address))
            
            get_data_node = current_entry[0].data   # str data encode utf 8
            json_data = json.loads(get_data_node.decode('utf-8'))

            passhash = _hash(password.encode('utf-8'))
            
            #init new data which udpate to database
            add_data = {
                username : passhash
            }
            json_data.update(add_data)

            new_data = json.dumps(json_data).encode('utf-8')
            addresses = context.set_state({edge_address: new_data})
            
            if len(addresses) < 1:
                raise InternalError("State Error")

    def _init_edge(self, context, edgehost):
        '''
        This funtion use to init database of edge device to test
        '''
        edge_address = self._get_object_address(edgehost)
        current_entry = context.get_state(edge_address)

        if current_entry == []:
            LOGGER('[+] init new_data for {}'.format(edgehost))
            init_data = {
                "test" : "test"
            }

            str_data = json.dumps(init_data)
            state_data = str_data.encode('utf-8')
            addresses = context.set_state({edge_address: state_data})

            if len(addresses) < 1:
                raise InternalError("State Error")
        else:
            LOGGER.info('[!] database existed')
            raise InternalError("State Error")

    def _get_object_address(self, from_key):
        return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + _hash(from_key.encode('utf-8'))[0:64]


def setup_loggers():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

def main():
    '''Entry-point function for the blockbee transaction processor.'''
    setup_loggers()
    try:
        # Register the transaction handler and start it.
        processor = TransactionProcessor(url='tcp://validator:4004')

        handler = blockbeeTransactionHandler(sw_namespace)

        processor.add_handler(handler)

        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
