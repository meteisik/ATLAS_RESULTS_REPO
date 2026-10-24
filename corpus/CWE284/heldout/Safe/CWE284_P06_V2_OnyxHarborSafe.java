import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxHarborSafe {
    private static boolean privateTrue = true;

    public void deleteOnyxHarborAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxHarborSafeSink()).applyOnyxHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxHarborSafeSink {
    public void applyOnyxHarborDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        try {
            PreparedStatement onyxHarborDelete = onyxHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHarborDelete.setString(1, data);
            if (authorized) {
                onyxHarborDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxHarborConnection.close();
        }
    }
}
