import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_SolarQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteSolarQuartzAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SOLAR_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_SolarQuartzChecker()).isAuthorized(requester);
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        try {
            PreparedStatement solarQuartzDelete = solarQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarQuartzDelete.setString(1, data);
            if (authorized) {
                solarQuartzDelete.executeUpdate();
            }
        } finally {
            solarQuartzConnection.close();
        }
    }
}

class CWE284_P07_V2_SolarQuartzChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
