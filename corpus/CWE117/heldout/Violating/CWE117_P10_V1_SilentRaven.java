import java.util.logging.Logger;

public class CWE117_P10_V1_SilentRaven {

    public static String data;

    public void handleSilentRaven() {
        data = System.getenv("SILENT_RAVEN_USER");
        (new CWE117_P10_V1_SilentRavenSink()).logSilentRaven();
    }
}

class CWE117_P10_V1_SilentRavenSink {
    public void logSilentRaven() {
        String data = CWE117_P10_V1_SilentRaven.data;
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + data);
    }
}
