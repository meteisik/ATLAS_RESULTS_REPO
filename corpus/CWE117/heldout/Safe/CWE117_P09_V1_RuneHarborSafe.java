import java.util.logging.Logger;

public class CWE117_P09_V1_RuneHarborSafe {

    static class Container {
        public String containerOne;
    }

    public void handleRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneHarborSafeSink()).logRuneHarbor(dataContainer);
    }
}

class CWE117_P09_V1_RuneHarborSafeSink {
    public void logRuneHarbor(CWE117_P09_V1_RuneHarborSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
