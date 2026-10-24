import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SolarFlare {

    public static String data;

    public void runSolarFlare() throws SQLException {
        data = System.getenv("SOLAR_FLARE_FILTER");
        (new CWE89_P10_V1_SolarFlareSink()).querySolarFlare();
    }
}

class CWE89_P10_V1_SolarFlareSink {
    public void querySolarFlare() throws SQLException {
        String data = CWE89_P10_V1_SolarFlare.data;
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        Statement solarFlareStatement = null;
        ResultSet solarFlareRows = null;
        try {
            solarFlareStatement = solarFlareConnection.createStatement();
            solarFlareRows = solarFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarFlareRows.getRow());
        } finally {
            if (solarFlareRows != null) {
                solarFlareRows.close();
            }
            if (solarFlareStatement != null) {
                solarFlareStatement.close();
            }
            solarFlareConnection.close();
        }
    }
}
