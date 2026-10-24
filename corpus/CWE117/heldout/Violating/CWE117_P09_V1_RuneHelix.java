import java.util.logging.Logger;

public class CWE117_P09_V1_RuneHelix {

    static class Container {
        public String containerOne;
    }

    public void handleRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneHelixSink()).logRuneHelix(dataContainer);
    }
}

class CWE117_P09_V1_RuneHelixSink {
    public void logRuneHelix(CWE117_P09_V1_RuneHelix.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeHelixLogger = Logger.getLogger("runeHelix.audit");
        runeHelixLogger.info("Login attempt for user " + data);
    }
}
