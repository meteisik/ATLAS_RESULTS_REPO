import java.util.logging.Logger;

public class CWE117_P10_V1_SilentOrbit {

    public static String data;

    public void handleSilentOrbit() {
        data = System.getenv("SILENT_ORBIT_USER");
        (new CWE117_P10_V1_SilentOrbitSink()).logSilentOrbit();
    }
}

class CWE117_P10_V1_SilentOrbitSink {
    public void logSilentOrbit() {
        String data = CWE117_P10_V1_SilentOrbit.data;
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + data);
    }
}
