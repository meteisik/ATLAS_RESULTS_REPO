import java.util.logging.Logger;

public class CWE117_P09_V1_RuneCometSafe {

    static class Container {
        public String containerOne;
    }

    public void handleRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneCometSafeSink()).logRuneComet(dataContainer);
    }
}

class CWE117_P09_V1_RuneCometSafeSink {
    public void logRuneComet(CWE117_P09_V1_RuneCometSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
