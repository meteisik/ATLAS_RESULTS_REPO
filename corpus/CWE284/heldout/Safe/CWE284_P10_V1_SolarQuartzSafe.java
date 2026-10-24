import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SolarQuartzSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSolarQuartzAccount() throws SQLException {
        data = System.getenv("SOLAR_QUARTZ_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SolarQuartzSafeSink()).applySolarQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SolarQuartzSafeSink {
    public void applySolarQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V1_SolarQuartzSafe.data;
        boolean authorized = CWE284_P10_V1_SolarQuartzSafe.authorized;
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        try {
            PreparedStatement solarQuartzDelete = solarQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarQuartzDelete.setString(1, data);
            if (authorized) {
                solarQuartzDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            solarQuartzConnection.close();
        }
    }
}
