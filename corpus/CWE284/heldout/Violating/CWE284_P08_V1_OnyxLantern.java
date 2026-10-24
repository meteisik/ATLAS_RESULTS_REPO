import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxLantern {

    public void deleteOnyxLanternAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_LANTERN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxLanternSink()).applyOnyxLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxLanternSink {
    public void applyOnyxLanternDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        try {
            PreparedStatement onyxLanternDelete = onyxLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLanternDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxLanternDelete.executeUpdate();
            }
        } finally {
            onyxLanternConnection.close();
        }
    }
}
