import java.util.logging.Logger;

public class CWE117_P09_V1_RuneNebulaSafe {

    static class Container {
        public String containerOne;
    }

    public void handleRuneNebula() {
        String data;
        data = System.getenv("RUNE_NEBULA_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneNebulaSafeSink()).logRuneNebula(dataContainer);
    }
}

class CWE117_P09_V1_RuneNebulaSafeSink {
    public void logRuneNebula(CWE117_P09_V1_RuneNebulaSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeNebulaLogger = Logger.getLogger("runeNebula.audit");
        runeNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
