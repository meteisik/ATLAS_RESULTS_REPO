import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SolarFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSolarFlare() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE89_P07_V2_SolarFlareSafeSource()).loadSolarFlare();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SolarFlareSafeSource {
    public String loadSolarFlare() {
        String data;
        data = "foo";
        return data;
    }
}
