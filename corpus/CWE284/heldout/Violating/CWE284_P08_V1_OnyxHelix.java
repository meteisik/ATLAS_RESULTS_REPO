import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxHelix {

    public void deleteOnyxHelixAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HELIX_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxHelixSink()).applyOnyxHelixDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxHelixSink {
    public void applyOnyxHelixDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        try {
            PreparedStatement onyxHelixDelete = onyxHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHelixDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxHelixDelete.executeUpdate();
            }
        } finally {
            onyxHelixConnection.close();
        }
    }
}
