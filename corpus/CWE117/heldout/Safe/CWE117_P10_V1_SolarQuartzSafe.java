import java.util.logging.Logger;

public class CWE117_P10_V1_SolarQuartzSafe {

    public static String data;

    public void handleSolarQuartz() {
        data = System.getenv("SOLAR_QUARTZ_USER");
        (new CWE117_P10_V1_SolarQuartzSafeSink()).logSolarQuartz();
    }
}

class CWE117_P10_V1_SolarQuartzSafeSink {
    public void logSolarQuartz() {
        String data = CWE117_P10_V1_SolarQuartzSafe.data;
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
