import java.util.logging.Logger;

public class CWE117_P07_V2_SolarFlare {
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
            data = (new CWE117_P07_V2_SolarFlareSource()).readSolarFlare();
        } else {
            data = null;
        }
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SolarFlareSource {
    public String readSolarFlare() {
        String data;
        data = System.getenv("SOLAR_FLARE_USER");
        return data;
    }
}
