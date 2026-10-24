import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SolarFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSolarFlareAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SOLAR_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SolarFlareChecker()).isAuthorized(requester);
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        try {
            PreparedStatement solarFlareDelete = solarFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarFlareDelete.setString(1, data);
            if (authorized) {
                solarFlareDelete.executeUpdate();
            }
        } finally {
            solarFlareConnection.close();
        }
    }
}

class CWE284_P07_V2_SolarFlareChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
