import java.util.logging.Logger;

public class CWE117_P06_V2_SilentRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSilentRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentRavenSink()).logSilentRaven(data);
    }
}

class CWE117_P06_V2_SilentRavenSink {
    public void logSilentRaven(String data) {
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + data);
    }
}
