import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxHarbor {

    private String onyxHarborAccountId;

    private boolean onyxHarborAuthorized;

    private void applyOnyxHarborDeletion() throws SQLException {
        String data = onyxHarborAccountId;
        boolean authorized = onyxHarborAuthorized;
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        try {
            PreparedStatement onyxHarborDelete = onyxHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHarborDelete.setString(1, data);
            onyxHarborDelete.executeUpdate();
        } finally {
            onyxHarborConnection.close();
        }
    }

    public void deleteOnyxHarborAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxHarborAccountId = data;
        onyxHarborAuthorized = isAuthorized(data);
        applyOnyxHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
