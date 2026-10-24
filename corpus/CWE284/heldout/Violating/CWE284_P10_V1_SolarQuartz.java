import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SolarQuartz {

    public static String data;

    public static boolean authorized;

    public void deleteSolarQuartzAccount() throws SQLException {
        data = System.getenv("SOLAR_QUARTZ_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SolarQuartzSink()).applySolarQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SolarQuartzSink {
    public void applySolarQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V1_SolarQuartz.data;
        boolean authorized = CWE284_P10_V1_SolarQuartz.authorized;
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        try {
            PreparedStatement solarQuartzDelete = solarQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarQuartzDelete.setString(1, data);
            solarQuartzDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            solarQuartzConnection.close();
        }
    }
}
