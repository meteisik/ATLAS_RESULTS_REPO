import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SolarFlare {

    public static String data;

    public static boolean authorized;

    public void deleteSolarFlareAccount() throws SQLException {
        data = System.getenv("SOLAR_FLARE_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SolarFlareSink()).applySolarFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SolarFlareSink {
    public void applySolarFlareDeletion() throws SQLException {
        String data = CWE284_P10_V1_SolarFlare.data;
        boolean authorized = CWE284_P10_V1_SolarFlare.authorized;
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        try {
            PreparedStatement solarFlareDelete = solarFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarFlareDelete.setString(1, data);
            solarFlareDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            solarFlareConnection.close();
        }
    }
}
