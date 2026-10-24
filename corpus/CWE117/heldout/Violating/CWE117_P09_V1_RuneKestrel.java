import java.util.logging.Logger;

public class CWE117_P09_V1_RuneKestrel {

    static class Container {
        public String containerOne;
    }

    public void handleRuneKestrel() {
        String data;
        data = System.getenv("RUNE_KESTREL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneKestrelSink()).logRuneKestrel(dataContainer);
    }
}

class CWE117_P09_V1_RuneKestrelSink {
    public void logRuneKestrel(CWE117_P09_V1_RuneKestrel.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeKestrelLogger = Logger.getLogger("runeKestrel.audit");
        runeKestrelLogger.info("Login attempt for user " + data);
    }
}
