from enum import Enum, auto

class InputType(Enum):
    URL = auto()
    DOMAIN = auto()
    FILE_HASH = auto()
    IP_ADDRESS = auto()
    EMAIL_ADDRESS = auto()
