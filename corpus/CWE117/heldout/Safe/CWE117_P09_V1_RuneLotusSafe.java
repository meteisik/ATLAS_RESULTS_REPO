import java.util.logging.Logger;

public class CWE117_P09_V1_RuneLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void handleRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneLotusSafeSink()).logRuneLotus(dataContainer);
    }
}

class CWE117_P09_V1_RuneLotusSafeSink {
    public void logRuneLotus(CWE117_P09_V1_RuneLotusSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeLotusLogger = Logger.getLogger("runeLotus.audit");
        runeLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
