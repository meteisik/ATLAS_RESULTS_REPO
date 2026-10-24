import java.util.logging.Logger;

public class CWE117_P10_V1_SolarFlareSafe {

    public static String data;

    public void handleSolarFlare() {
        data = System.getenv("SOLAR_FLARE_USER");
        (new CWE117_P10_V1_SolarFlareSafeSink()).logSolarFlare();
    }
}

class CWE117_P10_V1_SolarFlareSafeSink {
    public void logSolarFlare() {
        String data = CWE117_P10_V1_SolarFlareSafe.data;
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
