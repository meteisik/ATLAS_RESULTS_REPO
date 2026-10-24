import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxOrbitSafe {
    private static int privateFive = 5;

    private boolean checkOnyxOrbitAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxOrbitAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxOrbitAccess(data);
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        try {
            PreparedStatement onyxOrbitDelete = onyxOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxOrbitDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxOrbitDelete.executeUpdate();
            }
        } finally {
            onyxOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
