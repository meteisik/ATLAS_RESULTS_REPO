import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SolarFlareSafe {

    public void deleteSolarFlareAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SOLAR_FLARE_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SolarFlareSafeSink()).applySolarFlareDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SolarFlareSafeSink {
    public void applySolarFlareDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        try {
            PreparedStatement solarFlareDelete = solarFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                solarFlareDelete.executeUpdate();
            }
        } finally {
            solarFlareConnection.close();
        }
    }
}
