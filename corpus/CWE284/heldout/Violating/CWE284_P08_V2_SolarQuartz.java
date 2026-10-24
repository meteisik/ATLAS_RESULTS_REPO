import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SolarQuartz {

    public void deleteSolarQuartzAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("SOLAR_QUARTZ_ACCOUNT_ID");
            break;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SolarQuartzSink()).applySolarQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SolarQuartzSink {
    public void applySolarQuartzDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        try {
            PreparedStatement solarQuartzDelete = solarQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                solarQuartzDelete.executeUpdate();
            }
        } finally {
            solarQuartzConnection.close();
        }
    }
}
