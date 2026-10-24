import java.util.logging.Logger;

public class CWE117_P07_V2_SolarQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSolarQuartz() {
        String data;
        if (IO.staticFive == 5) {
            data = (new CWE117_P07_V2_SolarQuartzSafeSource()).readSolarQuartz();
        } else {
            data = null;
        }
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SolarQuartzSafeSource {
    public String readSolarQuartz() {
        String data;
        data = System.getenv("SOLAR_QUARTZ_USER");
        return data;
    }
}
