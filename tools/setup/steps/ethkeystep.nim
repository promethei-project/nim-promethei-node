import ../choicequestion
import ../app

proc genNewKey(app: App) =
  let
    privKey = "eth.key"
    addressFile = "eth.address"

  app.createNewEthKeyfile(privKey, addressFile)
  app.writeConfigLine("# Promethei node private key:")
  app.writeConfigLine("eth-private-key=" & privKey)
  app.writeConfigLine("# Public key saved to: " & addressFile & "\n")

proc writeExample(app: App) =
  app.writeConfigLine("# example Promethei node private key:")
  app.writeConfigLine("# eth-private-key=promethei_ethereum.key\n")

proc getEthKeyQuestion*(): ChoiceQuestion =
  return ChoiceQuestion(
    title: "Generate an Ethereum account?",
    options:
      @[
        ChoiceOption(
          title: "Generate new key-pair",
          description:
            @[
              "Generates a new private-key file and adds it to",
              "the Promethei node configuration.",
            ],
          warning: "",
          action: genNewKey,
        ),
        ChoiceOption(
          title: "Skip",
          description:
            @[
              "Setup will not generate a new key-pair for you.",
              "You can add your own key-file to,", "the configuration file manually.",
            ],
          warning: "",
          action: writeExample,
        ),
      ],
    defaultIndex: 0,
  )
