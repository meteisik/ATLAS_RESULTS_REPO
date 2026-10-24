import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxOrbit {

    public void deleteOnyxOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_ORBIT_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxOrbitSink()).applyOnyxOrbitDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxOrbitSink {
    public void applyOnyxOrbitDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        try {
            PreparedStatement onyxOrbitDelete = onyxOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxOrbitDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxOrbitDelete.executeUpdate();
            }
        } finally {
            onyxOrbitConnection.close();
        }
    }
}
