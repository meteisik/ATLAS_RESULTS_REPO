import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxRavenSafe {

    public void deleteOnyxRavenAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_RAVEN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxRavenSafeSink()).applyOnyxRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxRavenSafeSink {
    public void applyOnyxRavenDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        try {
            PreparedStatement onyxRavenDelete = onyxRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxRavenDelete.executeUpdate();
            }
        } finally {
            onyxRavenConnection.close();
        }
    }
}
