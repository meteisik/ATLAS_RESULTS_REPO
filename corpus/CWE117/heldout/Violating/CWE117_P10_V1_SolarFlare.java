import java.util.logging.Logger;

public class CWE117_P10_V1_SolarFlare {

    public static String data;

    public void handleSolarFlare() {
        data = System.getenv("SOLAR_FLARE_USER");
        (new CWE117_P10_V1_SolarFlareSink()).logSolarFlare();
    }
}

class CWE117_P10_V1_SolarFlareSink {
    public void logSolarFlare() {
        String data = CWE117_P10_V1_SolarFlare.data;
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + data);
    }
}
