import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonBeaconSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteCrimsonBeaconAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonBeaconSafeBase baseObject = new CWE284_P12_V2_CrimsonBeaconSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonBeaconSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonBeaconSafeRemover extends CWE284_P12_V2_CrimsonBeaconSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonBeacon");
        try {
            PreparedStatement crimsonBeaconDelete = crimsonBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonBeaconDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonBeaconDelete.executeUpdate();
            }
        } finally {
            crimsonBeaconConnection.close();
        }
    }
}
