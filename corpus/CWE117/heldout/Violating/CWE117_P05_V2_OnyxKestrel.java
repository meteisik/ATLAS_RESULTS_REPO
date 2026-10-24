import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxKestrel {
    private static boolean privateTrue = true;

    private String onyxKestrelData;

    private void logOnyxKestrel() {
        String data = onyxKestrelData;
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleOnyxKestrel() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_KESTREL_USER");
        } else {
            data = null;
        }
        onyxKestrelData = data;
        logOnyxKestrel();
    }
}
