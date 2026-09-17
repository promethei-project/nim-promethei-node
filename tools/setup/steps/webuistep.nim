import ../choicequestion
import ../app

proc setEnableWebUi(app: App) =
  app.webUi = true
  app.writeConfigLine("# Promethei-Project webUI support:")
  app.writeConfigLine("api-cors-origin=\"*\"")
  app.writeConfigLine("# URL: https://app.archivist.storage\n")

proc setNo(app: App) =
  app.webUi = false

proc getWebUiQuestion*(): ChoiceQuestion =
  return ChoiceQuestion(
    title: "Enable WebUI",
    options:
      @[
        ChoiceOption(
          title: "Yes",
          description:
            @["The Promethei node will support the Promethei-Project web interface."],
          warning: "Allows Cross-origin. WebApp hosted on Promethei-Project servers.",
          action: setEnableWebUi,
        ),
        ChoiceOption(
          title: "No",
          description:
            @["The Promethei node will not support the Promethei-Project webApp."],
          warning: "",
          action: setNo,
        ),
      ],
    defaultIndex: 1,
  )
