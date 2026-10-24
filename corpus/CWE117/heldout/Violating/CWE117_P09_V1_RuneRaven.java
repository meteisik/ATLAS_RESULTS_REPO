import java.util.logging.Logger;

public class CWE117_P09_V1_RuneRaven {

    static class Container {
        public String containerOne;
    }

    public void handleRuneRaven() {
        String data;
        data = System.getenv("RUNE_RAVEN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneRavenSink()).logRuneRaven(dataContainer);
    }
}

class CWE117_P09_V1_RuneRavenSink {
    public void logRuneRaven(CWE117_P09_V1_RuneRaven.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeRavenLogger = Logger.getLogger("runeRaven.audit");
        runeRavenLogger.info("Login attempt for user " + data);
    }
}
