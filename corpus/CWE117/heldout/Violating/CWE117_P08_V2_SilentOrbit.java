import java.util.logging.Logger;

public class CWE117_P08_V2_SilentOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSilentOrbit() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("SILENT_ORBIT_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentOrbitSink()).logSilentOrbit(dataArray);
    }
}

class CWE117_P08_V2_SilentOrbitSink {
    public void logSilentOrbit(String[] dataArray) {
        String data = dataArray[2];
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + data);
    }
}
