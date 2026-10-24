import java.util.logging.Logger;

public class CWE117_P07_V2_SilentOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSilentOrbit() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_SilentOrbitSource()).readSilentOrbit();
        } else {
            data = null;
        }
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentOrbitSource {
    public String readSilentOrbit() {
        String data;
        data = System.getenv("SILENT_ORBIT_USER");
        return data;
    }
}
