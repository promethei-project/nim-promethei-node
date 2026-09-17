import ../linequestion

proc getLineItemQuestions*(): seq[LineQuestion] =
  return
    @[
      LineQuestion(
        description: "Absolute or relative path where data will be stored",
        key: "data-dir",
        defaultValue: "./datadir",
      ),
      LineQuestion(
        description: "Network port used for Discovery (UDP) protocol",
        key: "disc-port",
        defaultValue: "8090",
      ),
      LineQuestion(
        description: "Multi-addresses of interfaces used for data (TCP) connections",
        key: "listen-addrs",
        defaultValue: "[\"/ip4/0.0.0.0/tcp/8070\"]",
      ),
      LineQuestion(
        description: "Network port used for Promethei node REST API",
        key: "api-port",
        defaultValue: "8080",
      ),
      LineQuestion(
        description: "Storage space limit in bytes that Promethei node can use",
        key: "storage-quota",
        defaultValue: "21000000000",
      ),
      LineQuestion(
        description: "Promethei node log file",
        key: "logfile",
        defaultValue: "promethei.log",
      ),
      LineQuestion(
        description: "Promethei node logging level",
        key: "log-level",
        defaultValue: "DEBUG",
      ),
    ]
