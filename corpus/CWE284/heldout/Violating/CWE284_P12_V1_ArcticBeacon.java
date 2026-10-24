import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ArcticBeacon {

    public void deleteArcticBeaconAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_BEACON_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ArcticBeaconBase baseObject = new CWE284_P12_V1_ArcticBeaconRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ArcticBeaconBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ArcticBeaconRemover extends CWE284_P12_V1_ArcticBeaconBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        try {
            PreparedStatement arcticBeaconDelete = arcticBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticBeaconDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticBeaconDelete.executeUpdate();
            }
        } finally {
            arcticBeaconConnection.close();
        }
    }
}
