import java.util.logging.Logger;

public class CWE117_P07_V2_SolarFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSolarFlare() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_SolarFlareSafeSource()).readSolarFlare();
        } else {
            data = null;
        }
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SolarFlareSafeSource {
    public String readSolarFlare() {
        String data;
        data = System.getenv("SOLAR_FLARE_USER");
        return data;
    }
}
