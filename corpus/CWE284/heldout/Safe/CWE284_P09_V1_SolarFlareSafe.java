import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SolarFlareSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSolarFlareAccount() throws SQLException {
        String data;
        data = System.getenv("SOLAR_FLARE_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SolarFlareSafeSink()).applySolarFlareDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SolarFlareSafeSink {
    public void applySolarFlareDeletion(CWE284_P09_V1_SolarFlareSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
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
