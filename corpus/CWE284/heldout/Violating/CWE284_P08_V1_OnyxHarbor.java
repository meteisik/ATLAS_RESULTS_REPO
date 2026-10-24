import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_OnyxHarbor {

    public void deleteOnyxHarborAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HARBOR_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_OnyxHarborSink()).applyOnyxHarborDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_OnyxHarborSink {
    public void applyOnyxHarborDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        try {
            PreparedStatement onyxHarborDelete = onyxHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHarborDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxHarborDelete.executeUpdate();
            }
        } finally {
            onyxHarborConnection.close();
        }
    }
}
