{.push raises: [].}

import ../../blocktype

type
  EngineError* = object of CatchableError
    address*: BlockAddress

  RetriesExhaustedEngineError* = object of EngineError
  StorageFailedEngineError* = object of EngineError
  QueueFailedEngineError* = object of EngineError
  RequestAbandonedEngineError* = object of EngineError
  NoPeerForBlockError* = object of EngineError
